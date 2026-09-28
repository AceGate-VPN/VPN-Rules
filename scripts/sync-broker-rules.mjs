#!/usr/bin/env node

import { access, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const brokerFiles = [
  "Futu.list.json",
  "Longbridge.list.json",
  "TigerFintech.list.json",
  "Schwab.list.json",
  "HKBroker.list.json",
];

const leafStringArrayFields = new Set([
  "source_ip_cidr",
  "ip_cidr",
  "domain",
  "domain_keyword",
  "domain_suffix",
  "geoip",
  "external",
  "port_range",
  "network",
  "inbound_tag",
]);

const allowedRuleFields = new Set([
  ...leafStringArrayFields,
  "target",
  "rule_set",
  "tag",
  "enable",
  "process_name",
]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateStringArray(value, field, fileName, ruleIndex) {
  assert(Array.isArray(value), `${fileName}: rules[${ruleIndex}].${field} 必须是数组`);
  assert(value.length > 0, `${fileName}: rules[${ruleIndex}].${field} 不能为空`);
  assert(
    value.every((item) => typeof item === "string" && item.length > 0),
    `${fileName}: rules[${ruleIndex}].${field} 必须只包含非空字符串`,
  );
  assert(
    new Set(value).size === value.length,
    `${fileName}: rules[${ruleIndex}].${field} 包含重复项`,
  );
}

function validateIpv4Cidr(value, fileName, ruleIndex) {
  const [address, prefixText, extra] = value.split("/");
  assert(extra === undefined && prefixText !== undefined, `${fileName}: 非法 CIDR ${value}`);
  const octets = address.split(".").map(Number);
  const prefix = Number(prefixText);
  assert(
    octets.length === 4 &&
      octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255) &&
      Number.isInteger(prefix) &&
      prefix >= 0 &&
      prefix <= 32,
    `${fileName}: rules[${ruleIndex}].ip_cidr 包含非法 CIDR ${value}`,
  );

  const numeric = octets.reduce((result, octet) => ((result << 8) | octet) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  assert(
    (numeric & mask) >>> 0 === numeric,
    `${fileName}: rules[${ruleIndex}].ip_cidr 不是规范网络地址 ${value}`,
  );
}

function validateRuleSet(value, fileName, ruleIndex) {
  assert(Array.isArray(value), `${fileName}: rules[${ruleIndex}].rule_set 必须是数组`);
  for (const [setIndex, item] of value.entries()) {
    assert(isObject(item), `${fileName}: rules[${ruleIndex}].rule_set[${setIndex}] 必须是对象`);
    for (const key of Object.keys(item)) {
      assert(
        key === "url" || key === "update_interval",
        `${fileName}: rules[${ruleIndex}].rule_set[${setIndex}] 包含未知字段 ${key}`,
      );
    }
    if (item.url !== undefined) {
      assert(
        typeof item.url === "string",
        `${fileName}: rules[${ruleIndex}].rule_set[${setIndex}].url 必须是字符串`,
      );
    }
    if (item.update_interval !== undefined) {
      assert(
        Number.isInteger(item.update_interval),
        `${fileName}: rules[${ruleIndex}].rule_set[${setIndex}].update_interval 必须是整数`,
      );
    }
  }
}

function validateDocument(document, fileName) {
  assert(isObject(document), `${fileName}: 顶层必须是对象`);
  assert(
    Object.keys(document).length === 1 && Object.hasOwn(document, "rules"),
    `${fileName}: 顶层必须严格符合 main.go 生成的 {"rules": [...]} 结构`,
  );
  assert(Array.isArray(document.rules), `${fileName}: rules 必须是数组`);
  assert(document.rules.length > 0, `${fileName}: rules 不能为空`);

  for (const [ruleIndex, rule] of document.rules.entries()) {
    assert(isObject(rule), `${fileName}: rules[${ruleIndex}] 必须是对象`);
    const fields = Object.keys(rule);
    assert(fields.length > 0, `${fileName}: rules[${ruleIndex}] 不能为空`);
    for (const field of fields) {
      assert(
        allowedRuleFields.has(field),
        `${fileName}: rules[${ruleIndex}] 包含 Leaf 不支持的字段 ${field}`,
      );
      if (leafStringArrayFields.has(field) || field === "process_name") {
        validateStringArray(rule[field], field, fileName, ruleIndex);
      } else if (field === "target" || field === "tag") {
        assert(
          typeof rule[field] === "string",
          `${fileName}: rules[${ruleIndex}].${field} 必须是字符串`,
        );
      } else if (field === "enable") {
        assert(
          typeof rule[field] === "boolean",
          `${fileName}: rules[${ruleIndex}].enable 必须是布尔值`,
        );
      } else if (field === "rule_set") {
        validateRuleSet(rule[field], fileName, ruleIndex);
      }
    }

    for (const cidr of rule.ip_cidr ?? []) {
      validateIpv4Cidr(cidr, fileName, ruleIndex);
    }
  }
}

async function exists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const sourceRoot = path.resolve(process.argv[2] ?? "");
  const targetRoot = path.resolve(process.argv[3] ?? process.cwd());
  assert(process.argv[2], "用法: node scripts/sync-broker-rules.mjs <源仓库目录> [目标仓库目录]");

  const sourceEntries = await readdir(sourceRoot, { withFileTypes: true });
  const sourceRuleDirs = sourceEntries.filter(
    (entry) => entry.isDirectory() && entry.name.toLowerCase() === "rules",
  );
  assert(
    sourceRuleDirs.length === 1,
    `源仓库必须且只能存在一个 Rules 或 rules 目录，实际为 ${sourceRuleDirs.length} 个`,
  );

  const sourceSiteDir = path.join(sourceRoot, sourceRuleDirs[0].name, "site");
  assert(await exists(sourceSiteDir), `源仓库缺少 ${sourceRuleDirs[0].name}/site 目录`);
  const targetSiteDir = path.join(targetRoot, "rules", "site");
  await mkdir(targetSiteDir, { recursive: true });

  const updated = [];
  for (const fileName of brokerFiles) {
    const sourcePath = path.join(sourceSiteDir, fileName);
    const targetPath = path.join(targetSiteDir, fileName);
    const content = await readFile(sourcePath, "utf8");
    let document;
    try {
      document = JSON.parse(content);
    } catch (error) {
      throw new Error(`${fileName}: JSON 解析失败: ${error.message}`);
    }
    validateDocument(document, fileName);

    const previous = await exists(targetPath) ? await readFile(targetPath, "utf8") : null;
    if (previous !== content) {
      await writeFile(targetPath, content, "utf8");
      updated.push(fileName);
    }
  }

  console.log(`校验文件数=${brokerFiles.length}`);
  console.log(`更新文件数=${updated.length}`);
  if (updated.length > 0) {
    console.log(`更新文件=${updated.join(",")}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});

# apnic-skills

APNIC（亚太互联网络信息中心）Go 语言 SDK，完整覆盖 APNIC 提供的所有公开数据服务与查询能力。

## 安装

```bash
go get github.com/cyberspacesec/apnic-skills
```

## 快速开始

```go
package main

import (
    "context"
    "fmt"
    "log"

    apnic "github.com/cyberspacesec/apnic-skills"
)

func main() {
    client := apnic.NewClient()
    ctx := context.Background()

    // RDAP 查询 IP
    network, err := client.RDAPLookupIP(ctx, "1.1.1.1")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Network: %s, Country: %s, Type: %s\n",
        network.Handle, network.Country, network.Type)

    // 获取 Delegated Stats
    entries, err := client.GetDelegatedEntries(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Total entries: %d\n", len(entries))

    // 链式过滤
    result := apnic.NewFilter(entries).
        ByCountry("CN").
        ByType("ipv4").
        ByStatus("allocated").
        Result()
    fmt.Printf("CN allocated IPv4 entries: %d\n", len(result))
}
```

## API 概览

### 1. Delegated Stats（IP/ASN 分配记录）

| 方法 | 说明 |
|------|------|
| `FetchDelegatedEntries(ctx)` | 获取最新标准版分配记录 |
| `GetDelegatedEntries(ctx)` | 带缓存的标准版分配记录 |
| `FetchDelegatedEntriesByDate(ctx, date)` | 获取指定日期的分配记录 |
| `FetchDelegatedResult(ctx, date)` | 获取完整结果（含 header/summary） |

### 2. Extended Delegated Stats（扩展版，含组织标识）

| 方法 | 说明 |
|------|------|
| `FetchExtendedEntries(ctx)` | 获取最新扩展版分配记录 |
| `GetExtendedEntries(ctx)` | 带缓存的扩展版分配记录 |
| `FetchExtendedEntriesByDate(ctx, date)` | 获取指定日期的扩展版 |
| `FetchExtendedResult(ctx, date)` | 获取完整结果（含 header/summary） |

### 3. Assigned Stats（按前缀大小聚合的分配统计）

| 方法 | 说明 |
|------|------|
| `FetchAssignedEntries(ctx)` | 获取最新分配统计 |
| `GetAssignedEntries(ctx)` | 带缓存的分配统计 |
| `FetchAssignedEntriesByDate(ctx, date)` | 获取指定日期的分配统计 |

### 4. Legacy Stats（历史遗留资源）

| 方法 | 说明 |
|------|------|
| `FetchLegacyEntries(ctx)` | 获取最新历史遗留记录 |
| `GetLegacyEntries(ctx)` | 带缓存的历史遗留记录 |
| `FetchLegacyEntriesByDate(ctx, date)` | 获取指定日期的历史遗留记录 |

### 5. RDAP 查询（结构化数据）

| 方法 | 说明 |
|------|------|
| `RDAPLookupIP(ctx, ip)` | RDAP IP 地址查询 |
| `RDAPLookupCIDR(ctx, cidr)` | RDAP CIDR 查询 |
| `RDAPLookupASN(ctx, asn)` | RDAP ASN 查询 |
| `RDAPLookupDomain(ctx, domain)` | RDAP 域名查询（反向 DNS） |
| `RDAPLookupEntity(ctx, handle)` | RDAP 实体/联系人查询 |
| `RDAPSearch(ctx, query)` | RDAP 全文搜索 |

### 6. Transfers（IP/ASN 转移记录）

| 方法 | 说明 |
|------|------|
| `FetchTransfers(ctx)` | 获取最新转移记录 |
| `GetTransfers(ctx)` | 带缓存的转移记录 |
| `FetchTransfersByYear(ctx, year)` | 获取指定年份的转移记录 |

### 7. Changes（资源变更记录）

| 方法 | 说明 |
|------|------|
| `FetchChanges(ctx)` | 获取最新变更记录 |
| `GetChanges(ctx)` | 带缓存的变更记录 |
| `FetchChangesByDate(ctx, date)` | 获取指定日期的变更记录 |

### 8. Whois 查询

| 方法 | 说明 |
|------|------|
| `QueryWhois(ctx, query)` | 原始 Whois 查询 |
| `QueryWhoisIP(ctx, ip)` | IP 地址 Whois 查询（返回解析结果） |
| `QueryWhoisASN(ctx, asn)` | ASN Whois 查询（返回解析结果） |
| `QueryWhoisWithFlags(ctx, query, flags)` | 带标志的 Whois 查询 |
| `ParseWhoisResponse(response)` | 解析 Whois 响应文本 |

### 9. 反向 DNS

| 方法 | 说明 |
|------|------|
| `ReverseDNS(ctx, ip)` | IP 反向 DNS 解析 |

### 10. 历史数据

| 方法 | 说明 |
|------|------|
| `FetchHistoricalDelegated(ctx, date)` | 获取指定日期的历史分配数据 |
| `FetchHistoricalExtended(ctx, date)` | 获取指定日期的历史扩展数据 |
| `FetchHistoricalAssigned(ctx, date)` | 获取指定日期的历史分配统计 |
| `FetchHistoricalLegacy(ctx, date)` | 获取指定日期的历史遗留数据 |
| `FetchDelegatedByYear(ctx, year)` | 获取指定年份的分配数据 |
| `FetchExtendedByYear(ctx, year)` | 获取指定年份的扩展数据 |
| `ListAvailableYears()` | 列出可用的历史数据年份 |

### 11. 数据校验

| 方法 | 说明 |
|------|------|
| `VerifyMD5(ctx, dataType, date)` | 校验数据文件 MD5 |
| `FetchMD5Checksum(ctx, dataType, date)` | 获取 MD5 校验值 |
| `FetchASCSignature(ctx, dataType, date)` | 获取 PGP 签名 |
| `FetchPublicKey(ctx)` | 获取 APNIC 公钥 |

### 12. 过滤与分组

| 方法 | 说明 |
|------|------|
| `FilterEntries(entries, country, resType)` | 按国家和类型过滤 |
| `FilterByStatus(entries, status)` | 按状态过滤 |
| `FilterByDateRange(entries, start, end)` | 按日期范围过滤 |
| `FilterExtendedByOpaqueID(entries, opaqueID)` | 按组织标识过滤 |
| `FilterExtendedByCountry(entries, country)` | 按国家过滤扩展版 |
| `FilterExtendedByType(entries, resType)` | 按类型过滤扩展版 |
| `FilterExtendedByStatus(entries, status)` | 按状态过滤扩展版 |
| `GroupByCountry(entries)` | 按国家分组 |
| `GroupExtendedByOpaqueID(entries)` | 按组织分组 |
| `GroupExtendedByCountry(entries)` | 按国家分组扩展版 |

### 13. 链式过滤 API

```go
// 标准版链式过滤
result := apnic.NewFilter(entries).
    ByCountry("CN").
    ByType("ipv4").
    ByStatus("allocated").
    ByDateRange(start, end).
    Result()

// 扩展版链式过滤
extResult := apnic.NewExtendedFilter(extEntries).
    ByCountry("JP").
    ByType("ipv6").
    ByOpaqueID("A92E1062").
    Result()
```

### 14. CIDR 计算

```go
// 标准版
cidr, err := entry.CIDR()

// 扩展版
cidr, err := extEntry.CIDR()

// 历史遗留版
cidr, err := legacyEntry.CIDR()
```

## 客户端配置

```go
client := apnic.NewClient(
    apnic.WithCacheTTL(10 * time.Minute),
    apnic.WithUserAgent("my-app/1.0"),
    apnic.WithRDAPBaseURL("https://rdap.apnic.net"),
    apnic.WithWhoisServer("whois.apnic.net:43"),
    apnic.WithWhoisTimeout(15 * time.Second),
    apnic.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
)
```

## License

MIT

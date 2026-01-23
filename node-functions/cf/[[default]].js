import express from "express";
import path from "path";
import fs from "fs";
import "dotenv/config";

const app = express();

// --- 1. 统一配置表 ---
const METRIC_MAP = {
    // 账号级流量/请求 (时间序列)
    l7Flow_flux: { name: "l7Flow_flux", sumid: "bytes", scope: "account" },
    l7Flow_outFlux: {
        name: "l7Flow_outFlux",
        sumid: "cachedBytes",
        scope: "account",
    },
    l7Flow_request: {
        name: "l7Flow_request",
        sumid: "requests",
        scope: "account",
    },
    l7Flow_inFlux: {
        name: "l7Flow_inFlux",
        sumid: "pageViews",
        scope: "account",
    },
    l7Flow_outcc: { name: "l7Flow_outcc", sumid: "threats", scope: "account" },
    l7Flow_cachedRequests: {
        name: "l7Flow_cachedRequests",
        sumid: "cachedRequests",
        scope: "account",
    },

    // 账号级分布数据 (Top N)
    // isDistribution: true 标识这是一种分类统计，不是时间序列
    l7Flow_outFlux_resourceType: {
        name: "l7Flow_outFlux_resourceType",
        sumid: "bytes",
        scope: "account",
        isDistribution: true,
        dimension: "edgeResponseContentTypeName",
    },
    l7Flow_request_resourceType: {
        name: "l7Flow_request_resourceType",
        sumid: "requests",
        scope: "account",
        isDistribution: true,
        dimension: "edgeResponseContentTypeName",
    },
    l7Flow_outFlux_country: {
        name: "l7Flow_outFlux_country",
        sumid: "bytes",
        scope: "account",
        isDistribution: true,
        dimension: "clientCountryName",
    },
    l7Flow_request_country: {
        name: "l7Flow_request_country",
        sumid: "requests",
        scope: "account",
        isDistribution: true,
        dimension: "clientCountryName",
    },
    function_requestCount: {
        name: "function_requestCount",
        sumid: "requests",
        scope: "account",
    },
    function_cpuCostTime: {
        name: "function_cpuCostTime",
        sumid: "cpuTimeUs",
        scope: "account",
    },

    // 域名级数据
    l7Flow_outFlux_domain: {
        name: "l7Flow_outFlux_domain",
        sumid: "bytes",
        scope: "zone",
    },
    l7Flow_request_domain: {
        name: "l7Flow_request_domain",
        sumid: "requests",
        scope: "zone",
    },
};
const ZONE_TOPN_CONFIG = {
    l7Flow_request_sip: "clientIP",
    l7Flow_request_ua_device: "clientRequestHTTPMethodName",
    l7Flow_request_ua_browser: "cacheStatus",
	l7Flow_request_zym: "clientRequestHTTPHost",
};
// --- 2. 辅助函数：获取凭证 ---
function getKeys() {
    let secretId = process.env.CFSECRET_ID;
    let secretKey = process.env.CFSECRET_KEY;
    let accountTag = process.env.CFACCOUNT_TAG;
    let zonetag = process.env.CFZONE_TAG;

    if (secretId && secretKey && accountTag && zonetag)
        return { secretId, secretKey, accountTag, zonetag };

    try {
        const keyPath = path.resolve(process.cwd(), "key.txt");
        if (fs.existsSync(keyPath)) {
            const content = fs.readFileSync(keyPath, "utf-8");
            content.split("\n").forEach((line) => {
                const [key, val] = line.split(/[：:]/);
                if (!val) return;
                const trimmedVal = val.trim();
                if (line.includes("cfid")) secretId = trimmedVal;
                if (line.includes("cfkey")) secretKey = trimmedVal;
                if (line.includes("cfuserid")) accountTag = trimmedVal;
                if (line.includes("zonetag")) zonetag = trimmedVal;
            });
        }
    } catch (err) {
        console.error("Error reading key.txt:", err);
    }
    return { secretId, secretKey, accountTag, zonetag };
}

// --- 3. 辅助函数：获取 Zone ID 和 域名映射 ---
async function fetchZones(secretId, secretKey) {
    const apiUrl =
        "https://api.cloudflare.com/client/v4/zones?status=active&per_page=50";
    const response = await fetch(apiUrl, {
        method: "GET",
        headers: {
            "X-Auth-Email": secretId,
            "X-Auth-Key": secretKey,
            "Content-Type": "application/json",
        },
    });

    if (!response.ok)
        throw new Error(`Fetch Zones Failed: ${response.statusText}`);

    const data = await response.json();
    const zoneIds = [];
    const idNameMap = {};

    if (Array.isArray(data?.result)) {
        for (const item of data.result) {
            zoneIds.push(item.id);
            idNameMap[item.id] = item.name;
        }
    }
    return { zoneIds, idNameMap };
}

// --- 4. 辅助函数：计算时间维度配置 ---
function getTimeConfig(reqStartTime, reqEndTime) {
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const start = reqStartTime || yesterday.toISOString();
    const end = reqEndTime || now.toISOString();

    const fromTime = new Date(start).getTime();
    const isLongTerm = now.getTime() - fromTime > 3 * 24 * 60 * 60 * 1000;

    let datasetMode, orderBy, dimensionKey, queryFrom, queryTo, filterObj;

    if (isLongTerm) {
        queryFrom = start.slice(0, 10);
        queryTo = end.slice(0, 10);
        datasetMode = "httpRequests1dGroups";
        orderBy = "date_ASC";
        dimensionKey = "date";
        filterObj = { date_geq: queryFrom, date_leq: queryTo };
    } else {
        queryFrom = start;
        queryTo = end;
        datasetMode = "httpRequests1hGroups";
        orderBy = "datetime_ASC";
        dimensionKey = "datetime";
        filterObj = { datetime_geq: queryFrom, datetime_leq: queryTo };
    }

    return {
        start,
        end,
        queryFrom,
        queryTo,
        datasetMode,
        orderBy,
        dimensionKey,
        isLongTerm,
        filterObj,
    };
}

// --- 5. 主路由逻辑 ---
app.get("/traffic", async (req, res) => {
    try {
        // 5.1 基础校验
        const { secretId, secretKey, accountTag, zonetag } = getKeys();
        if (!secretId || !secretKey || !accountTag || !zonetag) {
            return res.status(401).json({ error: "Missing credentials" });
        }

        const metricParam = req.query.metric;

         if (ZONE_TOPN_CONFIG[metricParam]) {
            const targetField = ZONE_TOPN_CONFIG[metricParam];
            const timeCfg = getTimeConfig(req.query.startTime, req.query.endTime);
            // 动态构建 GraphQL 查询
            const query = `
            query{
                viewer {
                    zones(filter: { zoneTag: "${zonetag}" }) {
                        httpRequestsAdaptiveGroups(
                            limit: 10,
                            orderBy: [count_DESC],
                            filter: {
                                datetime_geq: "${timeCfg.queryFrom}",
                                datetime_lt: "${timeCfg.queryTo}"
                            }
                        ) {
                             count
                            dimensions {
                                ${targetField}
                            }
                        }
                    }
                }
            }`;
            const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
                method: "POST",
                headers: { "X-Auth-Email": secretId, "X-Auth-Key": secretKey, "Content-Type": "application/json" },
                body: JSON.stringify({ query }),
            });
            const apiData = await response.json();
            
            // 增加 API 错误检查
            if (apiData.errors) {
                console.error("GraphQL Errors:", apiData.errors);
                return res.status(400).json(apiData);
            }
            const groups = apiData.data.viewer.zones[0].httpRequestsAdaptiveGroups;
            
            // 统一的数据清洗逻辑
            const detailData = groups.map(group => ({
                Key: group.dimensions[targetField],
                Value: group.count
            }));
            return res.json({ Data: [{ DetailData: detailData }] });
        }

        const config = METRIC_MAP[metricParam];
        if (!config) return res.status(400).json({ error: "Invalid metric" });

        const timeCfg = getTimeConfig(req.query.startTime, req.query.endTime);

        // ==========================================
        // 分支 A: Zone (域名) 级别查询 logic
        // ==========================================
        if (config.scope === "zone") {
            const { zoneIds, idNameMap } = await fetchZones(
                secretId,
                secretKey
            );

            if (zoneIds.length === 0) return res.json({ Data: [] });

            const query = `
            query getTrafficTrend($zoneIds: [String!], $from: String!) {
              viewer {
                zones(filter: { zoneTag_in: $zoneIds }) {
                  zoneTag
                  ${timeCfg.datasetMode}(
                    limit: 1000,
                    filter: { 
                        ${timeCfg.dimensionKey}_geq: $from
                    },
                    orderBy: [${timeCfg.orderBy}]
                  ) {
                    dimensions { ${timeCfg.dimensionKey} }
                    sum { ${config.sumid} }
                  }
                }
              }
            }
            `;

            const response = await fetch(
                "https://api.cloudflare.com/client/v4/graphql",
                {
                    method: "POST",
                    headers: {
                        "X-Auth-Email": secretId,
                        "X-Auth-Key": secretKey,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        query,
                        variables: {
                            zoneIds,
                            from: timeCfg.queryFrom,
                            to: timeCfg.queryTo, // 实际上原query只用了from, 如需严格需在query中加入to
                        },
                    }),
                }
            );

            const apiData = await response.json();
            if (apiData.errors) {
                console.error("GraphQL Errors:", apiData.errors);
                return res.status(400).json(apiData);
            }

            const zonesData = apiData?.data?.viewer?.zones || [];

            const resultList = zonesData.map((zone) => {
                const zoneId = zone.zoneTag;
                const domainName = idNameMap[zoneId] || zoneId;
                const dataArr = zone[timeCfg.datasetMode] || [];

                const totalVal = dataArr.reduce((acc, item) => {
                    return acc + (item.sum?.[config.sumid] || 0);
                }, 0);

                return { Key: domainName, Value: totalVal };
            });

            resultList.sort((a, b) => b.Value - a.Value);

            return res.json({
                Data: [{ DetailData: resultList }],
            });
        }

        // ==========================================
        // 分支 B: Account (账号) 级别查询 logic
        // ==========================================
        else {
            let query; // 声明在外部
            let httpMode, orderByMode, dimensionMode, filterMode;

            // 1. 分布类查询 (Resource Type 或 Country)
            if (config.isDistribution) {
                httpMode = "httpRequestsOverviewAdaptiveGroups"; // 使用概览分组获取 Top N
                orderByMode = `sum_${config.sumid}_DESC`;
                dimensionMode = config.dimension; // 动态维度: clientCountryName 或 edgeResponseContentTypeName
                filterMode = {
                    datetime_geq: timeCfg.start,
                    datetime_leq: timeCfg.end,
                };

                // 构建查询
                query = `
                    query GetAccountDistribution($accountTag: String, $filter: AccountHttpRequestsAdaptiveGroupsFilter_InputObject) {
                        viewer {
                            accounts(filter: {accountTag: $accountTag}) {
                                resultData: ${httpMode}(filter: $filter, limit: 100, orderBy: [${orderByMode}]) {
                                    sum { ${config.sumid} }
                                    dimensions { ${dimensionMode} }
                                }
                            }
                        }
                    }
                `;
            }
            // 2. 时间序列查询 (Trend)
            else {
                if (
                    req.query.metric == "function_requestCount" ||
                    req.query.metric == "function_cpuCostTime"
                ) {
                    httpMode = "workersInvocationsAdaptive";
                    orderByMode = "datetimeHour_ASC";
                    dimensionMode = "datetimeHour";
                } else {
                    httpMode = timeCfg.datasetMode;
                    orderByMode = timeCfg.orderBy;
                    dimensionMode = timeCfg.dimensionKey;
                }

                filterMode = timeCfg.filterObj;

                query = `
                    query GetAccountTraffic($accountTag: String, $filter: AccountHttpRequestsAdaptiveGroupsFilter_InputObject) {
                        viewer {
                            accounts(filter: {accountTag: $accountTag}) {
                                resultData: ${httpMode}(filter: $filter, limit: 1000, orderBy: [${orderByMode}]) {
                                    sum { ${config.sumid} }
                                    dimensions { ${dimensionMode} }
                                }
                            }
                        }
                    }
                `;
            }

            // 发起请求
            const response = await fetch(
                "https://api.cloudflare.com/client/v4/graphql",
                {
                    method: "POST",
                    headers: {
                        "X-Auth-Email": secretId,
                        "X-Auth-Key": secretKey,
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        query,
                        variables: { accountTag, filter: filterMode },
                    }),
                }
            );

            const apiData = await response.json();
            if (apiData.errors) {
                console.error("GraphQLErr:", apiData.errors);
                return res.status(400).json(apiData);
            }

            const accounts = apiData?.data?.viewer?.accounts;
            if (!accounts || accounts.length === 0)
                return res.json({ Data: [] });

            // 统一获取结果数组 (在query中别名为 resultData)
            const resultData = accounts[0].resultData || [];

            // 处理分布数据返回 (Country / ResourceType)
            if (config.isDistribution) {
                const detailData = resultData.map((item) => ({
                    Key: item.dimensions[config.dimension], // 动态获取维度值
                    Value: item.sum[config.sumid],
                }));
                // 排序
                detailData.sort((a, b) => b.Value - a.Value);

                return res.json({ Data: [{ DetailData: detailData }] });
            }

            // 处理时间序列数据返回 (Trend)
            // 如果有多个 locationTotals (比如按天/按小时)，这里做一个简单的时间轴合并
            const merged = {};

            // 注意：当前查询只取了 accounts[0]，如果后续有分页需求需调整
            resultData.forEach((item) => {
                const timeValue = item.dimensions[dimensionMode];
                const ts = Math.floor(Date.parse(timeValue) / 1000);
                merged[ts] = (merged[ts] || 0) + item.sum[config.sumid];
            });

            const detail = Object.entries(merged)
                .sort((a, b) => Number(a[0]) - Number(b[0]))
                .map(([ts, value]) => ({
                    Timestamp: parseInt(ts, 10),
                    Value: value,
                }));
            // ===== 仅在「>3天」且为 function_* 时，小时 → 天 =====
            const isFunctionMetric =
                metricParam === "function_requestCount" ||
                metricParam === "function_cpuCostTime";

            let finalDetail = detail;

            if (isFunctionMetric && timeCfg.isLongTerm) {
                const dayMerged = {};

                detail.forEach((item) => {
                    // Timestamp 是秒，转 UTC 日期
                    const day = new Date(item.Timestamp * 1000)
                        .toISOString()
                        .slice(0, 10); // YYYY-MM-DD

                    dayMerged[day] = (dayMerged[day] || 0) + item.Value;
                });

                finalDetail = Object.entries(dayMerged)
                    .sort((a, b) => a[0].localeCompare(b[0]))
                    .map(([day, value]) => ({
                        // 用当天 00:00 UTC 作为时间戳
                        Timestamp: Math.floor(
                            Date.parse(day + "T00:00:00Z") / 1000
                        ),
                        Value: value,
                    }));
            }

            const totalSum = detail.reduce((acc, curr) => acc + curr.Value, 0);
            return res.json({
                Data: [
                    {
                        TypeValue: [
                            {
                                Detail: finalDetail,
                                MetricName: config.name,
                                Sum: totalSum,
                            },
                        ],
                    },
                ],
            });
        }
    } catch (error) {
        console.error("Internal Error:", error);
        return res.status(500).json({ error: error.message });
    }
});
export default app;

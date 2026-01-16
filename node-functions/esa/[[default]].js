import express from 'express';
import path from 'path';
import fs from 'fs';
import 'dotenv/config';

const app = express();

// --- 1. 配置映射表 (替代长长的 if-else) ---
const METRIC_CONFIG = {
    // 序列数据 (TimeSeries)
    'l7Flow_flux': { action: 'DescribeSiteTimeSeriesData', field: 'Traffic', dimension: 'ALL', type: 'TS' },
    'l7Flow_inFlux': { action: 'DescribeSiteTimeSeriesData', field: 'RequestTraffic', dimension: 'ALL', type: 'TS' },
    'l7Flow_outFlux': { action: 'DescribeSiteTimeSeriesData', field: 'Traffic', dimension: 'ALL', type: 'TS' },
    'l7Flow_request': { action: 'DescribeSiteTimeSeriesData', field: 'Requests', dimension: 'ALL', type: 'TS' },

    // Top 数据 (TopData) - 归类处理
    'l7Flow_request_country': { field: 'Requests', dimension: 'ClientCountryCode' },
    'l7Flow_outFlux_country': { field: 'Traffic', dimension: 'ClientCountryCode' },
    'l7Flow_outFlux_province': { field: 'Traffic', dimension: 'ClientProvinceCode' },
    'l7Flow_request_province': { field: 'Requests', dimension: 'ClientProvinceCode' },
    'l7Flow_outFlux_statusCode': { field: 'Traffic', dimension: 'EdgeResponseStatusCode' },
    'l7Flow_request_statusCode': { field: 'Requests', dimension: 'EdgeResponseStatusCode' },
    'l7Flow_outFlux_domain': { field: 'Traffic', dimension: 'ClientRequestHost' },
    'l7Flow_request_domain': { field: 'Requests', dimension: 'ClientRequestHost' },
    'l7Flow_outFlux_url': { field: 'Traffic', dimension: 'ClientRequestPath' },
    'l7Flow_request_url': { field: 'Requests', dimension: 'ClientRequestPath' },
    'l7Flow_outFlux_resourceType': { field: 'Traffic', dimension: 'EdgeResponseContentType' },
    'l7Flow_request_resourceType': { field: 'Requests', dimension: 'EdgeResponseContentType' },
    'l7Flow_outFlux_sip': { field: 'Traffic', dimension: 'ClientIP' },
    'l7Flow_request_sip': { field: 'Requests', dimension: 'ClientIP' },
    'l7Flow_outFlux_referers': { field: 'Traffic', dimension: 'ClientRequestReferer' },
    'l7Flow_request_referers': { field: 'Requests', dimension: 'ClientRequestReferer' },
    'l7Flow_outFlux_ua_os': { field: 'Traffic', dimension: 'ClientOS' },
    'l7Flow_request_ua_os': { field: 'Requests', dimension: 'ClientOS' },
    'l7Flow_outFlux_ua': { field: 'Traffic', dimension: 'ClientRequestUserAgent' },
    'l7Flow_request_ua': { field: 'Requests', dimension: 'ClientRequestUserAgent' },
    'l7Flow_outFlux_ua_device': { field: 'Traffic', dimension: 'ClientRequestMethod' },
    'l7Flow_request_ua_device': { field: 'Requests', dimension: 'ClientRequestMethod' },
    'l7Flow_outFlux_ua_browser': { field: 'Traffic', dimension: 'EdgeCacheStatus' },
    'l7Flow_request_ua_browser': { field: 'Requests', dimension: 'EdgeCacheStatus' },
    'l7Flow_outFlux_urlquery': { field: 'Traffic', dimension: 'ClientRequestQuery' },
    'l7Flow_url_res_query': { field: 'Requests', dimension: 'ClientRequestQuery' },
};

// 默认配置填充 (TopData 默认 action)
Object.keys(METRIC_CONFIG).forEach(key => {
    if (!METRIC_CONFIG[key].action) {
        METRIC_CONFIG[key].action = 'DescribeSiteTopData';
        METRIC_CONFIG[key].type = 'TOP';
    }
});

// --- 2. 工具函数 ---

function getKeys() {
    let secretId = process.env.ESASECRET_ID;
    let secretKey = process.env.ESASECRET_KEY;
    if (secretId && secretKey) return { secretId, secretKey };

    try {
        const keyPath = path.resolve(process.cwd(), 'key.txt');
        if (fs.existsSync(keyPath)) {
            const content = fs.readFileSync(keyPath, 'utf-8');
            content.split('\n').forEach(line => {
                if (line.includes('accessKeyId')) secretId = line.split(/[：:]/)[1]?.trim();
                if (line.includes('accessKeySecret')) secretKey = line.split(/[：:]/)[1]?.trim();
            });
        }
    } catch (err) { console.error("Key read error:", err); }
    return { secretId, secretKey };
}

const percentEncode = (str) => 
    encodeURIComponent(str)
        .replace(/\+/g, '%20').replace(/\*/g, '%2A')
        .replace(/%7E/g, '~');

async function calculateSignature(secretKey, stringToSign) {
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(secretKey + '&');
    const messageBytes = encoder.encode(stringToSign);
    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );
    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);
    return btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));
}

// --- 3. 核心路由 ---

app.get('/traffic', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        if (!secretId || !secretKey) return res.status(500).json({ error: "Missing credentials" });

        const metricKey = req.query.metric;
        const config = METRIC_CONFIG[metricKey];
        if (!config) return res.status(400).json({ error: "Invalid metric parameter" });

        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const formatISO = (d) => d.toISOString().slice(0, 19) + 'Z';

        const params = {
            AccessKeyId: secretId,
            Action: config.action,
            EndTime: req.query.endTime || formatISO(now),
            Fields: JSON.stringify([{ FieldName: config.field, Dimension: [config.dimension] }]),
            Format: 'json',
            Interval: req.query.interval || "60",
            Limit: req.query.Limit || "10",
            Metric: config.dimension,
            SignatureMethod: 'HMAC-SHA1',
            SignatureNonce: Math.random().toString(36).substring(2) + Date.now(),
            SignatureVersion: '1.0',
            SiteId: req.query.siteId || '',
            StartTime: req.query.startTime || formatISO(yesterday),
            Timestamp: formatISO(now),
            Version: '2024-09-10'
        };

        // 签名生成
        const canonicalizedQuery = Object.keys(params).sort()
            .map(key => `${percentEncode(key)}=${percentEncode(params[key])}`)
            .join('&');
        
        const stringToSign = `GET&${percentEncode('/')}&${percentEncode(canonicalizedQuery)}`;
        params.Signature = await calculateSignature(secretKey, stringToSign);

        const apiUrl = `https://esa.cn-hangzhou.aliyuncs.com/?${new URLSearchParams(params)}`;
        const apiResponse = await fetch(apiUrl);
        
        if (!apiResponse.ok) {
            return res.status(apiResponse.status).json({ error: "Aliyun API error", detail: await apiResponse.text() });
        }

        const apiData = await apiResponse.json();

        // --- 4. 数据转换逻辑 ---

        if (apiData.Data && apiData.Data.length > 0) {
            if (config.type === 'TS') {
                // 处理 TimeSeries 类型
                const detailList = (apiData.Data[0].DetailData || []).map(item => ({
                    Value: item.Value || 0,
                    Timestamp: item.TimeStamp ? Math.floor(new Date(item.TimeStamp).getTime() / 1000) : 0
                }));

                apiData.Data[0].TypeValue = [{
                    MetricName: metricKey,
                    Sum: apiData.SummarizedData?.[0]?.Value || 0,
                    Detail: detailList
                }];
                delete apiData.Data[0].DetailData;
                delete apiData.SummarizedData;
            } else {
                // 处理 TopData 类型 (Country, Province, SIP, etc.)
                apiData.Data.forEach(dataItem => {
                    if (Array.isArray(dataItem.DetailData)) {
                        dataItem.DetailData = dataItem.DetailData.map(item => ({
                            Value: item.Value,
                            Key: item.DimensionValue, // 替换字段名
                            ...(item.TimeStamp && { TimeStamp: item.TimeStamp }) // 如果有时间戳则保留
                        }));
                    }
                });
            }
        }

        return res.json(apiData);

    } catch (error) {
        console.error('Final Catch Error:', error);
        return res.status(500).json({ error: `Server error: ${error.message}` });
    }
});

export default app;
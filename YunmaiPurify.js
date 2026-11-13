// 云麦好轻净化脚本 for Loon (http-response)
// 配合 YunmaiAdBlock.plugin 使用，由插件的 [Script] 段引用。
//
// 处理三件事：
//  1. 小轻AI：aiHelper/getSetting 返回 success:false，隐藏 AI 入口
//     （该入口是否显示由服务端配置驱动，返回失败即不展示）
//  2. 首页模块：first-page-module/v3/get.json 里去掉 moduleType 210「便宜好货」购物模块
//  3. 发现页：/community/ios/ 下的接口返回规整的空数据，列表页显示为空
//     （按原始 data 的形状回填空值：数组 -> []，含 rows 的对象 -> {rows:[],total:0}，其他 -> {}）
const url = $request.url;
let body = $response.body;
try {
  const obj = JSON.parse(body);
  const ok = {code: 0, msg: "OK", msgcn: "OK"};
  if (url.indexOf("aiHelper/getSetting") !== -1) {
    body = JSON.stringify({success: false, data: {}, result: ok});
  } else if (url.indexOf("first-page-module/v3/get.json") !== -1) {
    if (obj.data && Array.isArray(obj.data.moduleList)) {
      obj.data.moduleList = obj.data.moduleList.filter(function (m) { return m.moduleType !== 210; });
    }
    body = JSON.stringify(obj);
  } else if (url.indexOf("/community/ios/") !== -1) {
    const d = obj.data;
    let empty;
    if (Array.isArray(d)) empty = [];
    else if (d && typeof d === "object" && "rows" in d) empty = {rows: [], total: 0};
    else empty = {};
    body = JSON.stringify({data: empty, result: ok});
  }
} catch (e) {}
$done({body});

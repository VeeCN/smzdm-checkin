#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
什么值得买 (SMZDM) 自动签到 + 奖励领取 + 签到任务 + 免费转盘抽奖脚本
支持从环境变量 SMZDM_COOKIE 读取 Cookie（或单独配置 SMZDM_SESS / SMZDM_ID / SMZDM_DEVICE_ID / SMZDM_SK）
自动根据逆向出的 DES-ECB 算法动态计算 sk，并完成：
1. App 端每日签到 (https://user-api.smzdm.com/checkin)
2. App 端每日随机奖励 (https://user-api.smzdm.com/checkin/all_reward)
3. App 端连续签到额外奖励 (https://user-api.smzdm.com/checkin/extra_reward)
4. H5 签到日历查询与当日贴纸/日历节点奖励领取 (https://zhiyou.m.smzdm.com/activity/checkin_calendar/*)
5. H5 签到页每日浏览任务自动完成与领奖 (https://zhiyou.m.smzdm.com/task/task/*)
6. H5 每日签到免费转盘抽奖 (https://h5.smzdm.com/user/lottery/ajax_draw)
"""

import os
import sys
import time
import json
import base64
import hashlib
import urllib.parse
from http.cookies import SimpleCookie
import requests
from Crypto.Cipher import DES

sys.stdout.reconfigure(encoding="utf-8")

SIGN_KEY = "apr1$AwP!wRRT$gJ/q.X24poeBInlUJC"
DES_KEY = b"geZm53XA"
APP_VERSION = "11.1.98"
APP_REV = "1018"
DEFAULT_DEVICE_ID = "21307064331775793427182586d1621b6e25ee60028dcc945b4cc23640"
UA_APP = f"smzdm_android_V{APP_VERSION} rv:{APP_REV} (MEP-AN00;Android15;zh)smzdmapp"


def pkcs5_pad(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def calc_sk(smzdm_id: str, device_id: str, sess_decoded: str) -> str:
    """
    逆向自 com.smzdm.client.base.utils.s.p() -> A.h("geZm53XAspb02exN", smzdm_id + device_id, sess, null)
    明文格式: "{smzdm_id}{device_id}_{sess_decoded}"
    加密方式: DES-ECB / PKCS5Padding, 密钥前8字节 "geZm53XA", Base64编码
    """
    plain = f"{smzdm_id}{device_id}_{sess_decoded}".encode("utf-8")
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    encrypted = cipher.encrypt(pkcs5_pad(plain))
    return base64.b64encode(encrypted).decode("ascii")


def calc_sign(params: dict) -> str:
    """
    逆向自 App 签名算法:
    过滤非空参数 -> 按 key ASCII 升序排列 -> k=v&...&key=apr1$AwP!wRRT$gJ/q.X24poeBInlUJC -> MD5 大写
    """
    filtered = {k: str(v) for k, v in params.items() if v is not None and str(v) != ""}
    sorted_items = sorted(filtered.items(), key=lambda x: x[0])
    joined = "&".join(f"{k}={v}" for k, v in sorted_items)
    raw = f"{joined}&key={SIGN_KEY}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest().upper()


def parse_cookie_str(cookie_raw: str) -> dict:
    result = {}
    for part in cookie_raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip()
        # 过滤空值，防止同名空 sess="" 覆盖有效 sess
        if v:
            result[k] = v
    return result


def load_credentials() -> dict:
    cookie_raw = os.environ.get("SMZDM_COOKIE", "").strip()
    cookies = parse_cookie_str(cookie_raw) if cookie_raw else {}

    sess_raw = os.environ.get("SMZDM_SESS", "").strip() or cookies.get("sess", "")
    if not sess_raw:
        print("::error::未检测到有效的 sess 凭据，请配置 SMZDM_COOKIE 或 SMZDM_SESS。")
        sys.exit(1)

    sess_decoded = urllib.parse.unquote(sess_raw)
    sess_encoded = urllib.parse.quote(sess_decoded, safe="-_.")

    smzdm_id = os.environ.get("SMZDM_ID", "").strip() or cookies.get("smzdm_id", "")
    if not smzdm_id and "user" in cookies:
        user_dec = urllib.parse.unquote(cookies["user"])
        if "|" in user_dec:
            smzdm_id = user_dec.split("|")[-1].strip()

    device_id = (
        os.environ.get("SMZDM_DEVICE_ID", "").strip()
        or cookies.get("device_id", "")
        or DEFAULT_DEVICE_ID
    )

    sk = os.environ.get("SMZDM_SK", "").strip()
    if not sk:
        if not smzdm_id:
            print("::error::缺少 smzdm_id，无法自动计算 sk，请在 SMZDM_COOKIE 中包含 smzdm_id 或配置 SMZDM_ID。")
            sys.exit(1)
        sk = calc_sk(smzdm_id, device_id, sess_decoded)

    cookies["sess"] = sess_encoded
    cookies["smzdm_id"] = smzdm_id
    cookies["device_id"] = device_id
    cookies["f"] = "android"
    cookies["v"] = APP_VERSION
    cookies["weixin"] = "1"

    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items() if v)

    return {
        "sess_encoded": sess_encoded,
        "sess_decoded": sess_decoded,
        "smzdm_id": smzdm_id,
        "device_id": device_id,
        "sk": sk,
        "cookie_header": cookie_header,
    }


def app_post(url: str, cred: dict, extra_params: dict = None) -> dict:
    params = {
        "f": "android",
        "v": APP_VERSION,
        "weixin": "1",
        "time": str(int(time.time() * 1000)),
    }
    if extra_params:
        params.update(extra_params)
    params["sign"] = calc_sign(params)

    headers = {
        "User-Agent": UA_APP,
        "Cookie": cred["cookie_header"],
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    resp = requests.post(url, headers=headers, data=params, timeout=20)
    resp.raise_for_status()
    return resp.json()


def h5_get(url: str, cred: dict, params: dict = None) -> dict:
    q = {
        "version_code": APP_REV,
        "apk_partner_name": "smzdm",
    }
    if params:
        q.update(params)
    headers = {
        "User-Agent": UA_APP,
        "Cookie": cred["cookie_header"],
        "Referer": "https://zhiyou.m.smzdm.com/check_in",
        "Accept": "application/json, text/plain, */*",
    }
    resp = requests.get(url, headers=headers, params=q, timeout=20)
    resp.raise_for_status()
    return resp.json()


def h5_post(url: str, cred: dict, extra_data: dict = None) -> dict:
    data = {
        "f": "android",
        "device_id": cred["device_id"],
        "sess": cred["sess_decoded"],
        "smzdm_id": cred["smzdm_id"],
        "check_switch": "1",
        "project_id": "0",
    }
    if extra_data:
        data.update(extra_data)
    headers = {
        "User-Agent": UA_APP,
        "Cookie": cred["cookie_header"],
        "Referer": "https://zhiyou.m.smzdm.com/check_in",
        "Origin": "https://zhiyou.m.smzdm.com",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json, text/plain, */*",
    }
    resp = requests.post(url, headers=headers, data=data, timeout=20)
    resp.raise_for_status()
    return resp.json()


def run_app_checkin(cred: dict) -> bool:
    print("=== [1/5] 执行 App 端每日签到 ===")
    res = app_post(
        "https://user-api.smzdm.com/checkin",
        cred,
        {
            "sk": cred["sk"],
            "token": cred["sess_decoded"],
            "captcha": "",
            "touchstone_event": "",
        },
    )
    err_code = str(res.get("error_code", ""))
    err_msg = res.get("error_msg", "")
    data = res.get("data") or {}
    if err_code == "0":
        daily_num = data.get("daily_num", "?")
        cpoints = data.get("cpoints", "?")
        cexperience = data.get("cexperience", "?")
        cgold = data.get("cgold", "?")
        silver = data.get("pre_re_silver", "?")
        cards = data.get("cards", "?")
        print(
            f"[签到成功] 状态: {err_msg or '成功'} | 累计签到: {daily_num}天 | "
            f"积分: {cpoints} | 经验: {cexperience} | 金币: {cgold} | 碎银: {silver} | 补签卡: {cards}"
        )
        return True
    else:
        print(f"::error::[签到失败] error_code={err_code}, error_msg={err_msg}, raw={res}")
        return False


def run_app_rewards(cred: dict):
    print("\n=== [2/5] 领取 App 端签到附加奖励 ===")
    try:
        r_all = app_post("https://user-api.smzdm.com/checkin/all_reward", cred)
        print(f"[all_reward] code={r_all.get('error_code')} msg={r_all.get('error_msg')} data={r_all.get('data')}")
    except Exception as e:
        print(f"[all_reward] 请求异常: {e}")

    try:
        r_ext = app_post("https://user-api.smzdm.com/checkin/extra_reward", cred)
        print(f"[extra_reward] code={r_ext.get('error_code')} msg={r_ext.get('error_msg')} data={r_ext.get('data')}")
    except Exception as e:
        print(f"[extra_reward] 请求异常: {e}")


def run_h5_calendar_and_tasks(cred: dict):
    print("\n=== [3/5] 检查 H5 签到日历节点奖励 ===")
    activity_id = None
    try:
        view = h5_get("https://zhiyou.m.smzdm.com/activity/checkin_calendar/ajax_show_view", cred)
        if str(view.get("error_code")) == "0":
            vdata = view.get("data") or {}
            task_info = vdata.get("task") or {}
            activity_id = task_info.get("task_activity_id")
            axis_list = vdata.get("checkin_axis") or []
            for item in axis_list:
                if item.get("is_today"):
                    source = item.get("source")
                    is_claimed = item.get("is_claimed")
                    print(f"[今日日历节点] date={item.get('date')} source={source} is_claimed={is_claimed}")
                    if not is_claimed:
                        if source == "axis_sticker":
                            r_claim = h5_post("https://zhiyou.m.smzdm.com/activity/checkin_calendar/ajax_receive_sticker", cred)
                            print(f"  -> 领取今日贴纸奖励: {r_claim}")
                        elif source == "axis":
                            r_claim = h5_post("https://zhiyou.m.smzdm.com/activity/checkin_calendar/ajax_receive_reward", cred)
                            print(f"  -> 领取今日里程碑奖励: {r_claim}")
                        elif source == "campaign":
                            cid = item.get("campaign_record_id")
                            r_claim = h5_post(
                                "https://zhiyou.m.smzdm.com/activity/checkin_calendar/ajax_receive_activity",
                                cred,
                                {"campaign_record_id": str(cid)},
                            )
                            print(f"  -> 领取今日活动奖励: {r_claim}")
        else:
            print(f"[签到日历查询] code={view.get('error_code')} msg={view.get('error_msg')}")
    except Exception as e:
        print(f"[签到日历] 异常: {e}")

    print("\n=== [4/5] 执行 H5 签到中心每日浏览任务与领奖 ===")
    if not activity_id:
        print("[签到任务] 未获取到当前周期 task_activity_id，跳过。")
        return

    try:
        tinfo = h5_get(
            "https://zhiyou.m.smzdm.com/task/task/ajax_get_activity_info",
            cred,
            {"activity_id": activity_id},
        )
        tlist = ((tinfo.get("data") or {}).get("activity_task") or {}).get("default_list") or []
        print(f"[签到任务] 活动ID={activity_id}，共获取到 {len(tlist)} 个任务")
        for t in tlist:
            tid = t.get("task_id")
            tname = t.get("task_name")
            tstatus = int(t.get("task_status", 0))
            ttype = t.get("task_event_type", "")

            # status: 2=未完成, 3=可领奖, 4=已领奖
            if tstatus == 4:
                print(f"  - [{tname}] ({tid}): 已完成并领奖")
                continue

            if tstatus == 2:
                if ttype == "interactive.view.article":
                    aid = str(t.get("article_id") or "123615784")
                    cid = str(t.get("channel_id") or "76")
                    r_ev = h5_post(
                        "https://zhiyou.m.smzdm.com/task/task/ajax_event_view_article",
                        cred,
                        {"article_id": aid, "channel_id": cid},
                    )
                    print(f"  - [{tname}] ({tid}) 模拟浏览文章: code={r_ev.get('error_code')} msg={r_ev.get('error_msg')}")
                    time.sleep(1)
                    tstatus = 3
                elif ttype == "interactive.view.zhanwai":
                    r_ev = h5_post(
                        "https://zhiyou.m.smzdm.com/task/task/ajax_event_view_zhanwai",
                        cred,
                        {"task_id": tid},
                    )
                    print(f"  - [{tname}] ({tid}) 模拟浏览站外活动: code={r_ev.get('error_code')} msg={r_ev.get('error_msg')}")
                    time.sleep(1)
                    tstatus = 3
                else:
                    print(f"  - [{tname}] ({tid}): 未完成 (类型 {ttype} 需特定交互，跳过)")

            if tstatus == 3:
                r_rec = h5_post(
                    "https://zhiyou.m.smzdm.com/task/task/ajax_activity_task_receive",
                    cred,
                    {"task_id": tid},
                )
                rdata = r_rec.get("data") or {}
                print(
                    f"  - [{tname}] ({tid}) 领取任务奖励: code={r_rec.get('error_code')} "
                    f"msg={r_rec.get('error_msg') or rdata.get('gift_description') or rdata.get('reward_msg')}"
                )
    except Exception as e:
        print(f"[签到任务] 执行异常: {e}")


def run_free_lottery(cred: dict):
    print("\n=== [5/5] 执行每日签到免费转盘抽奖 ===")
    headers = {
        "User-Agent": UA_APP,
        "Cookie": cred["cookie_header"],
        "Referer": "https://h5.smzdm.com/user/lottery/checkin",
        "X-Requested-With": "XMLHttpRequest",
    }
    try:
        resp = requests.post("https://h5.smzdm.com/user/lottery/ajax_draw", headers=headers, timeout=20)
        resp.raise_for_status()
        res = resp.json()
        code = res.get("error_code")
        msg = res.get("error_msg", "")
        # 去除 HTML 标签便于日志阅读
        clean_msg = msg.replace('<span class="red">', "").replace("</span>", "").replace("<br />", " | ")
        print(f"[免费转盘抽奖] code={code} | 结果: {clean_msg}")
    except Exception as e:
        print(f"[免费转盘抽奖] 请求异常: {e}")


def main():
    cred = load_credentials()
    print(f"当前账号 smzdm_id: {cred['smzdm_id']} | 动态计算 sk 长度: {len(cred['sk'])}")
    checkin_ok = run_app_checkin(cred)
    run_app_rewards(cred)
    run_h5_calendar_and_tasks(cred)
    run_free_lottery(cred)
    if not checkin_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()

import json
import os

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.platform.astrbot_message import AstrBotMessage
from typing import Optional
import asyncio


class ApifoxModel:
    def __init__(self, approve: bool, flag: str, reason: Optional[str] = None) -> None:
        self.approve = approve
        self.flag = flag
        self.reason = reason


@register("astrbot_plugin_autoapprove", "囧囧JOJO", "群聊自动审批插件", "1.0.0")
class GroupAutoApprovePlugin(Star):
    def __init__(self, context: Context, config=None):
        super().__init__(context)
        # 默认配置
        self.config = {
        }

        # 如果传入了配置，则使用传入的配置
        if config:
            for key, value in config.items():
                if key in self.config:
                    self.config[key] = value
            logger.info(f"群聊自动审批插件插件配置加载成功")
        else:
            # 否则从context加载配置
            self._load_config()

        # Monkey patch AstrBotMessage类，确保所有实例都有session_id属性
        original_init = AstrBotMessage.__init__

        def patched_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            if not hasattr(self, "session_id") or not self.session_id:
                self.session_id = "unknown_session"

        # 应用monkey patch
        AstrBotMessage.__init__ = patched_init
        logger.info("已应用AstrBotMessage的monkey patch，确保session_id属性存在")

    def _load_config(self):
        """加载配置"""
        base_path = os.path.abspath(os.path.dirname(__file__))
        config_path = os.path.join(base_path, "config.json")
        if not os.path.exists(config_path):
            logger.warning(f"配置文件 {config_path} 不存在，使用默认配置")
            return

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # 确保所有值都是 set 类型
                for k, v in data.items():
                    if isinstance(v, list):
                        data[k] = set(v)
                self.config.update(data)
            logger.info(f"群聊自动审批插件配置已加载")
        except Exception as e:
            logger.error(f"加载群聊自动审批插件配置失败: {e}")

    def _save_config(self):
        """保存配置到上下文"""
        base_path = os.path.abspath(os.path.dirname(__file__))
        config_path = os.path.join(base_path, "config.json")
        try:
            # 将 set 转为 list 以兼容 JSON
            data = {k: list(v) for k, v in self.config.items()}
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"群聊自动审批插件配置已保存到 {config_path}")
        except Exception as e:
            logger.error(f"保存群聊自动审批插件配置失败: {e}")

    def set_session_id(self, event):
        """设置session_id属性"""
        if not hasattr(event, "message_obj") or not hasattr(event.message_obj, "raw_message"):
            return

        raw_message = event.message_obj.raw_message
        if not isinstance(raw_message, dict):
            return

        # 如果没有session_id属性，则根据请求类型添加
        if not hasattr(event.message_obj, "session_id") or not event.message_obj.session_id:
            if "group_id" in raw_message and raw_message["group_id"]:
                event.message_obj.session_id = str(raw_message["group_id"])
            elif "user_id" in raw_message and raw_message["user_id"]:
                event.message_obj.session_id = str(raw_message["user_id"])
            else:
                # 如果无法确定session_id，使用一个默认值
                event.message_obj.session_id = "unknown_session"

    @filter.event_message_type(filter.EventMessageType.ALL)
    async def handle_group_request(self, event: AstrMessageEvent):
        """处理群聊申请事件"""
        # 检查是否为请求事件
        if not hasattr(event, "message_obj") or not hasattr(event.message_obj, "raw_message"):
            return

        raw_message = event.message_obj.raw_message
        if not raw_message or not isinstance(raw_message, dict):
            return

        # 检查是否为群组请求事件
        if raw_message.get("post_type") != "request":
            return

        # 确保message_obj有session_id属性
        self.set_session_id(event)

        # 处理加群请求
        if raw_message.get("request_type") == "group" and raw_message.get("sub_type") == "add":
            await self.process_group_join_request(event, raw_message)

    @filter.command("加群自动审批")
    @filter.permission_type(filter.PermissionType.ADMIN)  # AstrBot 管理员权限标识
    async def handle_admin_command(self, event: AstrMessageEvent, action: str, group_id: str, qq_list: str = ""):
        """
        指令处理：/加群自动审批 add|remove 群号 QQ号1,QQ号2,...
        - action: add（添加）或 remove（删除）
        - group_id: 目标群号（字符串类型）
        - qq_list: 逗号分隔的QQ号字符串
        """
        if action not in ["add", "remove", "list"]:
            yield event.plain_result("操作类型错误！请使用 add 或 remove 或 list")
            return

        if action == "list":
            # 列出当前群的白名单
            group_whitelist = self.config.get(group_id, set())
            if not group_whitelist:
                yield event.plain_result(f"群{group_id}当前无白名单成员")
            else:
                yield event.plain_result(f"群{group_id}当前白名单数量：{len(group_whitelist)}")
            return

        # 解析QQ号列表（去空、去重）
        qq_list = {qq.strip() for qq in qq_list.split(",") if qq.strip()}
        if not qq_list:
            yield event.plain_result("QQ号列表为空！")
            return

        # 操作白名单
        group_whitelist = self.config.setdefault(group_id, set())
        if action == "add":
            group_whitelist.update(qq_list)
            self.config[group_id] = group_whitelist  # 确保更新后的白名单被保存
        else:
            group_whitelist.difference_update(qq_list)
            self.config[group_id] = group_whitelist
            # 若群白名单为空，删除该群记录
            if not group_whitelist:
                del self.config[group_id]

        # 保存配置
        self._save_config()  # 保存数据
        current_qqs = self.config.get(group_id, [])
        logger.info(f"群 {group_id} 当前白名单数量：{len(current_qqs)}, configs: {self.config}")
        yield event.plain_result(
            f"操作成功！群{group_id}当前白名单数量：{len(current_qqs)}"
        )

    async def process_group_join_request(self, event: AstrMessageEvent, request_data):
        """处理加群请求"""
        flag = request_data.get("flag", "")
        user_id = request_data.get("user_id", "")
        comment = request_data.get("comment", "")
        group_id = request_data.get("group_id", "")

        logger.info(f"收到加群请求: 用户ID={user_id}, 群ID={group_id}, 验证信息={comment}")

        # 检查是否在白名单中
        if str(group_id) not in self.config.keys():
            logger.info(f"群 {group_id} 不在自动审批配置中，跳过自动审批")
            return
        group_whitelist = self.config[str(group_id)]
        if str(user_id) in group_whitelist:
            logger.info(f"用户 {user_id} 在群 {group_id} 的白名单中，自动同意加群请求")
            await self.approve_request(event, flag, True)
            return
        logger.info(f"用户 {user_id} 不在群 {group_id} 的白名单中，暂不处理")
        return

    async def approve_request(self, event: AstrMessageEvent, flag, approve=True, reason=""):
        """同意或拒绝请求"""
        try:
            # 确保message_obj有session_id属性
            self.set_session_id(event)

            # 检查是否为aiocqhttp平台
            if event.get_platform_name() == "aiocqhttp":
                # 使用NapCat API格式
                from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
                assert isinstance(event, AiocqhttpMessageEvent)
                client = event.bot

                # 创建ApifoxModel实例
                api_model = ApifoxModel(
                    approve=approve,
                    flag=flag,
                    reason=reason
                )

                # 调用NapCat API
                payloads = {
                    "flag": api_model.flag,
                    "sub_type": "add",
                    "approve": api_model.approve,
                    "reason": api_model.reason if api_model.reason else ""
                }

                await client.call_action('set_group_add_request', **payloads)
                return True
            # 兼容其他平台的处理方式
            elif event.bot and hasattr(event.bot, "call_action"):
                await event.bot.call_action(
                    "set_group_add_request",
                    flag=flag,
                    sub_type="add",
                    approve=approve,
                    reason=reason
                )
                return True
            return False
        except Exception as e:
            logger.error(f"处理群聊申请失败: {e}")
            return False

    async def terminate(self):
        """插件被卸载/停用时调用"""
        logger.info("群聊自动审批插件插件已停用")

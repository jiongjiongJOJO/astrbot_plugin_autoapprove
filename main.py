import json
from typing import Optional
from astrbot.api import logger
from astrbot.api.star import Context, Star, register
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.core.platform.astrbot_message import AstrBotMessage
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent


class ApifoxModel:
    def __init__(self, approve: bool, flag: str, reason: Optional[str] = None) -> None:
        self.approve = approve
        self.flag = flag
        self.reason = reason


@register("astrbot_plugin_autoapprove", "囧囧JOJO", "群聊自动审批插件", "1.1.0")
class GroupAutoApprovePlugin(Star):
    def __init__(self, context: Context, config=None):
        super().__init__(context)
        # 默认配置
        self.config = config

        if isinstance(self.config.get("whitelist"), str):
            self.config["whitelist"] = json.loads(
                self.config.get("whitelist", "[]"), strict=False
            )
        logger.info('[加群自动审批插件] 成功加载配置: {}'.format(self.config))

        # Monkey patch AstrBotMessage类，确保所有实例都有session_id属性
        original_init = AstrBotMessage.__init__

        def patched_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            if not hasattr(self, "session_id") or not self.session_id:
                self.session_id = "unknown_session"

        # 应用monkey patch
        AstrBotMessage.__init__ = patched_init
        logger.info("已应用AstrBotMessage的monkey patch，确保session_id属性存在")

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

    @filter.command_group("加群自动审批")
    def plugin_group_command(self):
        pass

    @plugin_group_command.command("add", alias={'添加', '新增', '增加'})
    @filter.permission_type(filter.PermissionType.ADMIN)  # AstrBot 管理员权限标识
    async def add_white_list(self, event: AstrMessageEvent, group_id: str, qq_list: str):
        """
        指令处理：添加群聊自动审批白名单
        """
        """
        :param: group_id: 目标群号（字符串类型）
        :param: qq_list: 逗号分隔的QQ号字符串
        """

        # 解析QQ号列表（去空、去重）
        qq_list = {qq.strip() for qq in qq_list.split(",") if qq.strip()}
        if not qq_list:
            yield event.plain_result("QQ号列表为空！")
            return

        # 操作白名单
        group_whitelist = self.get_group_whitelist(group_id)
        group_whitelist.extend(qq_list)
        group_whitelist = list(set(group_whitelist))
        self.update_group_whitelist(group_id, group_whitelist)
        logger.info(f"配置即将保存，self.config: {self.config}")
        self.config.save_config()  # 保存数据
        current_qqs = self.get_group_whitelist(group_id)
        logger.info(f"群 {group_id} 添加白名单成功，当前白名单数量：{len(current_qqs)}")
        yield event.plain_result(
            f"白名单添加成功！群{group_id}当前白名单数量：{len(current_qqs)}"
        )

    @plugin_group_command.command("remove", alias={'删除', '移除', 'rm', 'del', 'clear'})
    @filter.permission_type(filter.PermissionType.ADMIN)  # AstrBot 管理员权限标识
    async def remove_white_list(self, event: AstrMessageEvent, group_id: str, qq_list: str = ""):
        """
        指令处理：删除群聊自动审批白名单（参数为空则删除目标群聊全部白名单）
        """
        """
        :param: group_id: 目标群号（字符串类型）
        :param: qq_list: 逗号分隔的QQ号字符串(可为空)
        """
        group_id = str(group_id).strip()
        qq_list = str(qq_list).strip()
        if qq_list:
            # 解析QQ号列表（去空、去重）
            # 解析
            qq_list_parms = {qq.strip() for qq in qq_list.split(",") if qq.strip()}
            # 操作白名单
            group_whitelist = self.get_group_whitelist(group_id)
            # 将qq_list_parms中的QQ号从群白名单中删除, 如果不存在则忽略
            group_whitelist = [qq for qq in group_whitelist if qq not in qq_list_parms]
            self.update_group_whitelist(group_id, group_whitelist)
            # 若群白名单为空，删除该群记录
            if not group_whitelist:
                self.del_group_whitelist(group_id)
        else:
            self.del_group_whitelist(group_id)  # 删除群白名单记录

        # 保存配置
        self.config.save_config()  # 保存数据
        current_qqs = self.get_group_whitelist(group_id)
        if not qq_list:
            logger.info(f"群 {group_id} 白名单清空")
            yield event.plain_result(f"群{group_id}白名单已清空！")
        else:
            logger.info(f"群 {group_id} 当前白名单数量：{len(current_qqs)}")
            yield event.plain_result(
                f"白名单清除操作成功！群{group_id}当前白名单数量：{len(current_qqs)}"
            )

    @plugin_group_command.command("list", alias={'列出', '查看', 'show', 'ls'})
    @filter.permission_type(filter.PermissionType.ADMIN)  # AstrBot 管理员权限标识
    async def get_white_list(self, event: AstrMessageEvent, group_id: str):
        """
        指令处理：列出群聊自动审批白名单数量
        """
        """
        :param: group_id: 目标群号（字符串类型）
        """
        # 列出当前群的白名单
        group_whitelist = self.get_group_whitelist(group_id)
        group_whitelist.sort()
        if not group_whitelist:
            yield event.plain_result(f"群{group_id}当前无白名单成员")
        else:
            # 将group_whitelist按照180个元素一份，拆分成多份
            plains = []
            for i in range(0, len(group_whitelist), 180):
                plains.append(
                    ','.join(group_whitelist[i:i + 180])
                )
            yield event.plain_result(f"群{group_id}当前白名单数量：{len(group_whitelist)}")
            for plain in plains:
                yield event.plain_result(plain)
            logger.info('[debug]: 群{}当前白名单数量：{}'.format(group_id, len(group_whitelist)))
        return

    @plugin_group_command.command("manual", alias={'手动处理', '手动'})
    @filter.permission_type(filter.PermissionType.ADMIN)  # AstrBot 管理员权限标识
    async def manual_process_requests(self, event: AstrMessageEvent, list_count: int = 50):
        """
        手动处理未响应的加群请求
        """
        client = event.bot  # 得到 client
        payloads = {
            "count": list_count
        }
        ret = await client.api.call_action('get_group_system_msg', **payloads)  # 调用 协议端  API
        yield event.plain_result(
            '待处理加群请求数: {}'.format(
                len(ret.get('join_requests', [])),
            )
        )
        # 统计
        processed_count = 0
        for request in ret.get('join_requests', []):
            if request.get('checked', True):
                continue
            request_data = {
                "flag": request.get("request_id", ""),
                "user_id": request.get("invitor_uin", ""),
                "comment": request.get("message", ""),
                "group_id": request.get("group_id", "")
            }
            # 处理加群请求
            await self.process_group_join_request(event, request_data)
            processed_count += 1
        yield event.plain_result("手动处理加群请求完成, 共处理请求数: " + str(processed_count))

    async def process_group_join_request(self, event: AstrMessageEvent, request_data):
        """处理加群请求"""
        flag = request_data.get("flag", "")
        user_id = request_data.get("user_id", "")
        comment = request_data.get("comment", "")
        group_id = request_data.get("group_id", "")

        logger.info(
            f"收到加群请求: "
            f"请求标识={flag}, "
            f"用户ID={user_id}, "
            f"群ID={group_id}, "
            f"验证信息={comment}".replace('\r', '').replace('\n', '')
        )

        # 检查是否在白名单中
        if str(group_id) not in self.get_group_list():
            logger.info(f"群 {group_id} 不在自动审批配置中，跳过自动审批")
            return
        group_whitelist = self.get_group_whitelist(str(group_id))
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

    def get_group_list(self):
        """获取当前配置中的群聊白名单"""
        whitelists = self.config.get("whitelist", {})
        group_list = []
        for group in whitelists:
            group_id = group.get("group_id")
            if group_id:
                group_list.append(group_id)
        return group_list

    def get_group_whitelist(self, group_id: str):
        """获取指定群聊的白名单"""
        for group in self.config.get("whitelist", []):
            if group.get("group_id") == group_id:
                return group.get("whitelist", [])
        return []

    def update_group_whitelist(self, group_id: str, whitelist: list):
        """更新指定群聊的白名单"""
        for group in self.config.get("whitelist", []):
            if group.get("group_id") == group_id:
                group["whitelist"] = whitelist
                return
        # 如果群聊不存在，则添加新的群聊记录
        self.config["whitelist"].append({
            "group_id": group_id,
            "whitelist": whitelist
        })

    def del_group_whitelist(self, group_id: str):
        """删除指定群聊的白名单"""
        for group in self.config.get("whitelist", []):
            if group.get("group_id") == group_id:
                self.config["whitelist"].remove(group)
                return

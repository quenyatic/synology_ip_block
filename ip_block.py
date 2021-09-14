import ipaddress
import sqlite3
import env_loader, os, re, time
from datetime import datetime, timedelta, timezone

class IpBlock():
    AUTH_PATH = ""
    ACCOUNT_PATH = ""
    IP_BLOCK_DB_PATH = ""
    BLOCK_EXPIRE_DAY = 0
    EXCEPT_IP_LIST = []

    allow_user_list = []
    db_cursur = None
    db_conn = None

    block_update_count = 0
    
    def __init__(self) -> None:
        self.AUTH_PATH = os.getenv('AUTH_PATH')
        self.ACCOUNT_PATH = os.getenv('ACCOUNT_PATH')
        self.IP_BLOCK_DB_PATH = os.getenv('IP_BLOCK_DB_PATH')
        self.BLOCK_EXPIRE_DAY = int(os.getenv('BLOCK_EXPIRE_DAY', 0))
        self.EXCEPT_IP_LIST = os.getenv('EXCEPT_IP_LIST', '127.0.0.1,').split(',')

        self.get_allow_user()
        self.init_database()

    def init_database(self):
        self.db_conn = sqlite3.connect(self.IP_BLOCK_DB_PATH)
        self.db_cursur = self.db_conn.cursor()

    def get_allow_user(self) -> list:
        '''
        허용된 사용자 리스트
        '''
        if os.path.isfile(self.ACCOUNT_PATH):
            with open(self.ACCOUNT_PATH, mode='rt', encoding="utf8") as fh:
                account_list = fh.readlines()
                for user in account_list:
                    user_temp = [x.strip() for x in user.split(":")]
                    if user_temp[1] != '*' and user_temp[7] == '':
                        self.allow_user_list.append(user_temp[0])

        return self.allow_user_list

    def get_auth_fail(self) -> list:
        '''
        로그인 실패 정보
        '''
        pattern = re.compile('(\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}[\-|\+]\d{2}\:\d{2}).*?authentication failure.*?rhost=((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*?user=(.*?)[\n|\r]')

        start_time = int(datetime.now(timezone.utc).timestamp()) - 1200

        block_address_list = []

        if os.path.isfile(self.AUTH_PATH):
            with open(self.AUTH_PATH, mode='rt', encoding="utf8") as fh:
                for log in fh.readlines():
                    if log.lower().find('authentication failure') < 0:
                        continue

                    matches = pattern.match(log)
                    if matches is not None:
                        # 2021-08-04T00:49:38+09:00
                        set_time = int(datetime.fromisoformat(matches[1]).timestamp())
                        ip_address = matches[2]
                        account = matches[3]

                        # 20분 넘은 내용은 무시
                        if set_time < start_time:
                            continue

                        # 차단 제외 아이피
                        if ip_address in self.EXCEPT_IP_LIST:
                            continue

                        # 내부 아이피 넘기기
                        if self.check_private_ip(ip_address) is True:
                            continue

                        # 등록된 아이디는 넘기기
                        if account in self.allow_user_list:
                            continue

                        # 이미 등록된 아이피 넘기기
                        if self.get_blocked_ip(ip_address):
                            continue

                        # 차단해야 되는 아이피 리스트
                        block_address_list.append(ip_address)
            fh.close()
        return list(set(block_address_list))

    def get_blocked_ip(self, ipv4) -> bool:
        self.db_cursur.execute("SELECT * FROM AutoBlockIP WHERE IP = ? AND Deny = 1", (ipv4, ))
        rows = self.db_cursur.fetchall()
        if len(rows) > 0:
            return True
        else:
            return False

    def check_private_ip(self, ipv4) -> bool:
        return ipaddress.ip_address(ipv4).is_private

    def ipv4_to_ipv6(self, ipv4) -> str:
        numbers = list(map(int, ipv4.split('.')))
        ipv6 = '0000:0000:0000:0000:0000:FFFF:{:02x}{:02x}:{:02x}{:02x}'.format(*numbers).upper()
        return ipv6

    def set_block_ip(self, ipv4):
        # 아이피 차단 등록

        if self.block_update_count >= 5:
            return False
        
        set_deny = 1
        set_type = 0
        ipStd = self.ipv4_to_ipv6(ipv4)
        current_time = int(time.time())

        expire_time = self.BLOCK_EXPIRE_DAY
        if self.BLOCK_EXPIRE_DAY != 0:
            expire_time = current_time + self.BLOCK_EXPIRE_DAY * 86400
        
        try:
            insert_data = [ipv4, current_time, expire_time, set_deny, ipStd, set_type]
            self.db_cursur.execute("INSERT INTO AutoBlockIP (IP, RecordTime, ExpireTime, Deny, IPStd, Type) VALUES (?, ?, ?, ?, ?, ?)", insert_data)
        except sqlite3.OperationalError:
            self.block_update_count = self.block_update_count + 1
            print('sqlite3 error ip : %s, try : %d' % (ipv4, self.block_update_count))
            self.db_conn.commit()
            self.set_block_ip(ipv4)

        self.db_conn.commit()

if __name__ == "__main__":
    env_loader.EnvLoader()

    ip_block = IpBlock()
    block_ip_list = ip_block.get_auth_fail()
    for ip_address in block_ip_list:
        print("block ip : ",ip_address)
        ip_block.block_update_count = 0
        ip_block.set_block_ip(ip_address)
    ip_block.db_conn.close()
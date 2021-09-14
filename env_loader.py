import os

class EnvLoader():
    def __init__(self) -> None:
        self.get_file_read()
        pass

    def get_file_read(self):
        env_path = os.path.dirname(os.path.realpath(__file__)) + '/.env'
        if os.path.isfile(env_path):
            with open(env_path, mode='rt', encoding="utf8") as fh:
                read_text = fh.readlines()
                for config in read_text:
                    config = config.strip()                    
                    if len(config) == 0 or config[0] == '#' :
                        continue

                    config_temp = config.split('=')
                    os.environ[config_temp[0]] = config_temp[1]
            pass
        else:
            print('set env file')
            pass
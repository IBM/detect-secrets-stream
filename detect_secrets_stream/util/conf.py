import configparser
import os
from functools import lru_cache


class ConfUtil():

    @staticmethod
    @lru_cache()
    def load_github_conf(config_file_name=os.getenv('GD_GITHUB_CONF')):
        try:
            config = ConfUtil._load_conf(config_file_name)
            return config['github']
        except Exception:
            return {'tokens': '', 'host': '', 'admin_config': ''}

    @staticmethod
    @lru_cache()
    def load_basic_auth_conf(config_file_name=os.getenv('GD_BASIC_AUTH_CONF')):
        config = ConfUtil._load_conf(config_file_name)
        return config['basic_auth']

    @staticmethod
    @lru_cache()
    def load_db_conf(config_file_name=os.getenv('GD_DB_CONF')):
        config = ConfUtil._load_conf(config_file_name)
        return config['db']

    @staticmethod
    @lru_cache()
    def load_kafka_conf(config_file_name=os.getenv('GD_KAFKA_CONF')):
        config = ConfUtil._load_conf(config_file_name)
        return config['kafka']

    @staticmethod
    @lru_cache()
    def load_vault_conf(config_file_name=os.getenv('GD_VAULT_CONF')):
        config = ConfUtil._load_conf(config_file_name)
        return config['vault']

    @staticmethod
    @lru_cache()
    def load_iam_conf(config_file_name=os.getenv('GD_IAM_CONF_FILENAME')):
        config = ConfUtil._load_conf(config_file_name)
        return config['iam']

    @staticmethod
    @lru_cache()
    def load_revoker_urls_conf(config_file_name=os.getenv('GD_REVOKER_URLS_CONF')):
        config = ConfUtil._load_conf(config_file_name)
        return config['revoker-urls']

    @staticmethod
    @lru_cache()
    def load_email_conf(config_file_name=os.getenv('GD_EMAIL_CONF')):
        config = ConfUtil._load_conf(config_file_name)
        return config['email']

    @staticmethod
    def _load_conf(config_file_name: str):
        '''
        Load configuration from a file

        It's not necessary to use lru_cache here because the helper functions which call _load_conf are already using it
        '''
        try:
            config = configparser.ConfigParser()
            config.read(config_file_name)
            return config
        except Exception as e:
            print(f'Unable to load configuration file {config_file_name}')
            raise e

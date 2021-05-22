import datetime
import logging
import os
import tempfile

from ..secret_corpus_db.gd_db_tools import connect_db
from ..secret_corpus_db.gd_db_tools import truncate_vmt_report
from ..util.log_util import LogUtil
from .box_uploader import BoxClient
from .gd_report_generator import GdReportGenerator


class VmtReport(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def gen_report_name(self):
        return os.path.join(tempfile.gettempdir(), f'Exposed-Tokens-{datetime.date.today()}.csv')

    def send_csv(self, box_folder_id, org_set_filter=None, include_private_repo_tokens=True):
        if not box_folder_id:
            return

        file_basename = self.gen_report_name()

        gd_report_generator = GdReportGenerator()
        gd_report_generator.generate_csv_from_db(
            file_basename,
            org_set_filter=org_set_filter,
            include_private_repo_tokens=include_private_repo_tokens,
        )

        box_client = BoxClient()
        box_client.upload_file(box_folder_id, file_basename)

    def generate_db_report(self, include_private_repo_tokens=True):
        # cleanup existing table
        conn = connect_db()
        truncate_vmt_report(conn)

        # generate report
        gd_report_generator = GdReportGenerator(
            include_security_focals=True,
            include_repo_visibility=True,
        )
        gd_report_generator.generate_vmt_report_in_db(
            include_private_repo_tokens=include_private_repo_tokens,
        )


if __name__ == '__main__':  # pragma: no cover
    LogUtil.set_root_logger_json()

    vmt_report = VmtReport()
    # generate CSV for VMT
    vmt_report.send_csv(
        box_folder_id=os.getenv('GD_VMT_BOX_FOLDER_ID'),
        org_set_filter=None,
        include_private_repo_tokens=os.getenv(
            'FF_INCLUDE_PRIVATE_IN_VMT_REPORT', False,
        ) == 'true',
    )
    # generate CSV for Watson
    vmt_report.send_csv(
        box_folder_id=os.getenv('GD_WATSON_BOX_FOLDER_ID'),
        org_set_filter='watson',
        include_private_repo_tokens=True,
    )
    # generate report in DB for VMT
    vmt_report.generate_db_report(
        include_private_repo_tokens=os.getenv(
            'FF_INCLUDE_PRIVATE_IN_VMT_REPORT', False,
        ) == 'true',
    )

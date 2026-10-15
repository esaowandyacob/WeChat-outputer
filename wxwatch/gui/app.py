"""GUI 入口。

用法：.venv/bin/python main.py gui
    或 sudo ./run_gui.sh（root 直启：全程无需密码，退出时产物 chown 回真实用户）
"""

import sys

from PySide6.QtWidgets import QApplication

from wxwatch.gui.main_window import MainWindow


def run():
    # 仅支持 root 运行（Linux）：run_gui.sh 已自动 sudo 提权；
    # 直接 python main.py gui 启动的非 root 进程一律拒绝，不存在降级模式。
    from wxwatch.gui.privilege import is_admin
    if sys.platform != "win32" and not is_admin():
        sys.exit("[ERR] 请以 root 运行：./run_gui.sh（脚本会自动 sudo 提权，全程免密码）")

    # root 直启：启动时与退出前把密钥/产物还给真实用户
    from wxwatch.gui.privilege import chown_to_real_user
    root_mode = is_admin() and sys.platform != "win32"
    if root_mode:
        import atexit
        from wxwatch.gui.backend import (CONFIG_FILE, KEYS_FILE, MIRROR_DIR,
                                         OUTPUT_DIR)
        paths = (KEYS_FILE, CONFIG_FILE, OUTPUT_DIR, MIRROR_DIR)
        chown_to_real_user(*paths)
        atexit.register(chown_to_real_user, *paths)

    app = QApplication(sys.argv)
    app.setApplicationName("wxwatch")
    app.setOrganizationName("wxwatch")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()

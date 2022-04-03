import traceback
import scapy.all as scapy
from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import QMessageBox
import mainwindow as mainwindow
import second_window as second_window
import sys
import psutil
from PyQt5 import QtWidgets

# import darktheme
# from darktheme.widget_template import DarkPalette
# app.setPalette(DarkPalette())

iface_to_sniff = 0
filter_to_sniff = 'IP'


def log_uncaught_exceptions(ex_cls, ex, tb):
    """Отслеживание ошибок и вывод информации в MessageBox"""
    text = '{}: {}:\n'.format(ex_cls.__name__, ex)
    text += ''.join(traceback.format_tb(tb))
    QMessageBox.critical(None, 'Ошибка', text)
    quit()


sys.excepthook = log_uncaught_exceptions


class SniffThread(QThread):
    def __init__(self, parent=None):
        super(SniffThread, self).__init__(parent)
        self.running = True
        self.my_sniffer = Sniff()

    def run(self):

        while self.running:
            QThread.sleep(1)
            # print(1)
            self.my_sniffer.sniff()


class Sniff:

    def __init__(self):
        global iface_to_sniff, filter_to_sniff
        _bpf_filter_args = []
        self.iface_to_sniff = iface_to_sniff
        self.filter_to_sniff = filter_to_sniff
        self.processing = True


    def process_sniffed(self, packet):
         print(packet)

    def sniff(self):
        # scapy.sniff(iface=self.iface_to_sniff, store=False, prn=self.process_sniffed, filter=self.filter_to_sniff)
        # self.sniffer.start()
        # sniffer.stop()
        while self.processing:
            scapy.sniff(count=10, iface=self.iface_to_sniff, store=False, prn=self.process_sniffed, filter=self.filter_to_sniff)
            # self.sniffer = scapy.AsyncSniffer(count=1, iface=self.iface_to_sniff, store=False, prn=self.process_sniffed,
            #                          filter=self.filter_to_sniff)

    def stop_sniff(self):
        # self.sniffer.stop()
        self.processing = False

class Window_2(QtWidgets.QWidget, second_window.Ui_Dialog):
    def __init__(self, parent=None):
        super(Window_2, self).__init__(parent)
        uic = second_window.Ui_Dialog()
        self.ui = uic
        uic.setupUi(self)
        uic.start_button.clicked.connect(self.start_sniff)
        uic.stop_button.clicked.connect(self.stop_sniff)
        self.second_thread = SniffThread()

    def start_sniff(self):
        global iface_to_sniff, filter_to_sniff
        # print('нажатие на старт')
        # print(iface_to_sniff)

        if not self.second_thread.running:
            self.second_thread.running = True
        #     self.second_thread.start()
        # else:
        self.second_thread.start()

    def stop_sniff(self):
        print('нажатие на стоп')
        # self.second_thread.running = False
        # self.second_thread.exit()
        self.second_thread.my_sniffer.stop_sniff()


    # def closeEvent(self, event):
    #     # Переопределить colseEvent
    #     reply = QMessageBox.question \
    #         (self, 'Вы нажали на крестик',
    #          "Вы уверены, что хотите уйти?",
    #          QMessageBox.Yes,
    #          QMessageBox.No)
    #     if reply == QMessageBox.Yes:
    #         event.accept()
    #     else:
    #         event.ignore()


class Main(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(Main, self).__init__(parent)
        uic = mainwindow.Ui_mainWindow()
        uic.setupUi(self)
        self.ui = uic
        uic.pushButton.clicked.connect(self.show_window_2)
        uic.comboBox_2.currentTextChanged.connect(Main.cmbbox_2_onchange)
        uic.lineEdit.hide()
        self.check_net_addrs()

    def show_window_2(self):  # открытие 2  окна
        global iface_to_sniff, filter_to_sniff
        iface_to_sniff = self.ui.comboBox_1.currentText()
        filter_to_sniff = self.ui.comboBox_2.currentText()
        self.inst = Window_2()
        self.inst.show()

    def cmbbox_2_onchange(self):
        """Отслеживание изменения ComboBox_2 и TODO активация ввода параметра вручную"""
        pass
        # print('запуск')
        # print(str(self.comboBox_2.currentText()))
        # if self.ui.comboBox_2.currentText() == 'Ввести вручную':
        #     self.ui.lineEdit.show()

    def check_net_addrs(self):
        """Просмотр доступных сетевых интерфейсов и добавление списка в ComboBox_1"""
        addrs = psutil.net_if_addrs()
        # print(addrs.keys())
        self.ui.comboBox_1.addItems(addrs)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = Main()
    w.show()
    sys.exit(app.exec_())

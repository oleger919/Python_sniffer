import traceback
import scapy.all as scapy
from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import QMessageBox, QTableWidgetItem
from scapy.layers.inet import IP
import mainwindow as mainwindow
import second_window as second_window
import sys
import psutil
from PyQt5 import QtWidgets

# import darktheme
# from darktheme.widget_template import DarkPalette
# app.setPalette(DarkPalette())

iface_to_sniff = ''
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
            self.my_sniffer.sniff()


class Sniff:

    def __init__(self):
        global iface_to_sniff, filter_to_sniff
        self.iface_to_sniff = iface_to_sniff
        self.filter_to_sniff = filter_to_sniff
        self.processing = True
        self.packet_list = []

    def process_sniffed(self, packet):
        global root_window
        if self.processing:
            if packet.haslayer(IP):
                add_to_table_list = [str(packet[IP].src), str(packet[IP].dst)]
                add_to_table_list.append('TCP') if packet.proto == 6 else add_to_table_list.append(str(packet.proto))
                print(add_to_table_list)
                print(packet.show())

                rows_count = root_window.inst.ui.snifftable.rowCount()
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 0, QTableWidgetItem(add_to_table_list[0]))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 1, QTableWidgetItem(add_to_table_list[1]))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 2, QTableWidgetItem(add_to_table_list[2]))
                root_window.inst.ui.snifftable.insertRow(rows_count)
                # self.packet_list.append(packet)

    def sniff(self):
        global iface_to_sniff, filter_to_sniff
        self.iface_to_sniff = iface_to_sniff
        self.filter_to_sniff = filter_to_sniff
        while self.processing:
            scapy.sniff(count=10, iface=self.iface_to_sniff, filter=self.filter_to_sniff, store=False,
                        prn=self.process_sniffed)

    def stop_sniff(self):
        self.processing = False
        scapy.wrpcap(filename='test', pkt=self.packet_list)


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
        self.ui.what_iface_sniff.setText(iface_to_sniff)
        if not self.second_thread.running:
            self.second_thread.running = True
            self.second_thread.my_sniffer.processing = True
        self.second_thread.start()

    def stop_sniff(self):
        print('нажатие на стоп')
        self.second_thread.running = False
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
        self.inst = Window_2()

    def show_window_2(self):  # открытие 2  окна
        global iface_to_sniff, filter_to_sniff
        iface_to_sniff = self.ui.comboBox_1.currentText()
        if self.ui.comboBox_2.currentText() == 'Без фильтра':
            filter_to_sniff = ''
        else:
            filter_to_sniff = self.ui.comboBox_2.currentText()
        self.inst.show()

    def cmbbox_2_onchange(self):
        """Отслеживание изменения ComboBox_2 и TODO активация ввода параметра вручную"""
        # if self.ui.comboBox_2.currentText() == 'Ввести вручную':
        #     self.ui.lineEdit.show()
        # else:
        #     self.ui.lineEdit.hide()
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
    root_window = Main()
    root_window.show()
    sys.exit(app.exec_())

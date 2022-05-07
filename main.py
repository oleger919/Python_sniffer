import os
import platform
import time
import traceback
import scapy.all as scapy
from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import QMessageBox, QTableWidgetItem
from scapy.layers.inet import IP
from scapy.layers.http import Raw
import sys
import psutil
from PyQt5 import QtWidgets, QtCore
from scapy.utils import hexdump, PcapReader
from shutil import move as move_file
from shutil import copyfile
from platform import system
import mainwindow as mainwindow
import second_window_bar as second_window
import wait as wait_msg

# import darktheme
# from darktheme.widget_template import DarkPalette
# app.setPalette(DarkPalette())

iface_to_sniff = ''
filter_to_sniff = 'IP'
scapy_proto_dict = {6: 'TCP',
                    17: 'UDP',
                    1: 'ICMP',
                    # 0: 'IP',
                    }


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
        my_file = open("sniffed", "w+")
        my_file.close()
        self.my_sniffer = Sniff()

    def run(self):
        """ parameter "mode" : 0 - reading file, 1 - real-time sniff"""
        # print('mode in sniffthread = ', self.mode)
        while self.running:
            self.my_sniffer.sniff()


class Sniff:

    def __init__(self):
        global iface_to_sniff, filter_to_sniff
        self.iface_to_sniff = iface_to_sniff
        self.filter_to_sniff = filter_to_sniff
        self.processing = True
        self.packet_list = []
        # self.please_wait = WaitWindow()
        # self.please_wait.show()
        # self.please_wait.hide()


    def process_sniffed(self, packet):
        global root_window
        if self.processing:
            scapy.wrpcap(filename='sniffed', pkt=packet, append=True)
            if packet.haslayer(IP):
                add_to_table_list = {'source': str(packet[IP].src),
                                     'destination': str(packet[IP].dst),
                                     'protocol': '',
                                     'length': str(packet[IP].len),
                                     'raw': 'None',
                                     'packet': str(packet),
                                     'info': packet.show()
                                     }
                if packet.proto in scapy_proto_dict.keys():
                    add_to_table_list['protocol'] = scapy_proto_dict[packet.proto]
                else:
                    add_to_table_list['protocol'] = str(packet.proto)
                if packet.haslayer(Raw):
                    add_to_table_list['raw'] = str(packet[Raw].load)
                # print(add_to_table_list)
                # print(packet.show())
                # print(hexdump(packet))

                rows_count = root_window.inst.ui.snifftable.rowCount()
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 0, QTableWidgetItem(add_to_table_list['source']))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 1,
                                                       QTableWidgetItem(add_to_table_list['destination']))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 2,
                                                       QTableWidgetItem(add_to_table_list['protocol']))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 3, QTableWidgetItem(add_to_table_list['length']))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 4, QTableWidgetItem(add_to_table_list['raw']))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 5, QTableWidgetItem(add_to_table_list['packet']))
                root_window.inst.ui.snifftable.setItem(rows_count - 1, 6, QTableWidgetItem(add_to_table_list['info']))

                root_window.inst.ui.snifftable.insertRow(rows_count)
                # self.packet_list.append(packet)
                scapy.wrpcap('sniffed', packet, append=True)

    def sniff(self, mode=1):
        """ parameter "mode" : 0 - reading file, 1 - real-time sniff"""
        global iface_to_sniff, filter_to_sniff
        self.iface_to_sniff = iface_to_sniff
        self.filter_to_sniff = filter_to_sniff
        # print(mode)
        if mode == 1:
            while self.processing:
                scapy.sniff(count=10, iface=self.iface_to_sniff, filter=self.filter_to_sniff, store=False,
                            prn=self.process_sniffed)
        elif mode == 0:
            pcap_file = QtWidgets.QFileDialog.getOpenFileName()
            scapy.sniff(offline=pcap_file[0], prn=self.process_sniffed, store=0)
            QMessageBox.information(None, 'Анализатор трафика', 'Загрузка из файла прошла успешно')
        else:
            QMessageBox.critical(None, 'Ошибка', 'Передано неверное значение параметра mode')

    def stop_sniff(self):
        self.processing = False

    def read_from_pcap(self):
        pcap_file = QtWidgets.QFileDialog.getOpenFileName()
        # print(pcap_file)
        # for packet in PcapReader(pcap_path):
        #     try:
        #         if packet[TCP].dport == 80:
        #
        #     except Exception as e:
        #         pass


class WaitWindow(QtWidgets.QDialog, wait_msg.Ui_Dialog):
    def __init__(self, parent=None):
        super(WaitWindow, self).__init__(parent)
        uic = wait_msg.Ui_Dialog()
        self.ui = uic
        uic.setupUi(self)


class Window_2(QtWidgets.QMainWindow, second_window.Ui_MainWindow):
    def __init__(self, parent=None):
        super(Window_2, self).__init__(parent)
        uic = second_window.Ui_MainWindow()
        self.ui = uic
        uic.setupUi(self)
        uic.start_button.clicked.connect(self.start_sniff)
        uic.stop_button.clicked.connect(self.stop_sniff)
        self.cols = uic.snifftable.columnCount()

        uic.open_file_action.triggered.connect(self.open_pcap_file)
        uic.save_file_action.triggered.connect(self.save_pcap_file)
        uic.show_info_action.triggered.connect(self.show_info)
        uic.clear_table_action.triggered.connect(self.clear_snifftable)

        uic.snifftable.hideColumn(5)
        uic.snifftable.hideColumn(6)
        uic.snifftable.hideColumn(7)

        self.second_thread = SniffThread()

        self.mouse_press = None
        uic.snifftable.cellPressed[int, int].connect(self.clickedRowColumn)

        # uic.snifftable.hideColumn(0)

    def show_info(self):
        QMessageBox.information(None, 'О программе', 'Данная программа представляет собой '
                                                     'пассивный сниффер для анализа '
                                                     'трафика в локальной сети \n'
                                                     'Разработчик: Олег Баранов')

    def clear_snifftable(self):
        self.ui.snifftable.setRowCount(0)
        self.ui.snifftable.setRowCount(1)

    def clickedRowColumn(self, r, c):
        if self.ui.snifftable.currentItem() is not None:
            row = self.ui.snifftable.currentItem().row()
            item = (self.ui.snifftable.item(row, 5)).text()
            hexitem = hexdump(item, dump=True)
            self.ui.hexdump_edit.setText(hexitem)

    def open_pcap_file(self):
        # print('ща откроем')
        self.stop_sniff()
        self.ui.snifftable.setRowCount(0)
        self.ui.snifftable.setRowCount(1)
        # self.start_sniff(mode=0)
        self.my_sniffer = Sniff()
        # self.please_wait = WaitWindow()
        # self.please_wait.show()
        # self.please_wait.hide()
        self.my_sniffer.sniff(mode=0)

    def save_pcap_file(self):
        fname = QtWidgets.QFileDialog.getSaveFileName(self, 'Open file', '/packets', 'PCAP файл (*.pcapng)')[0]
        filename = ''
        # print(platform.system())
        if platform.system() == 'Windows':
            filename = '\sniffed'
        elif platform.system() == 'Linux' or 'Darwin':
            filename = '/sniffed'
        current_dir = os.path.dirname(os.path.abspath(__file__)) + filename
        copyfile(current_dir, fname)

    def start_sniff(self, mode=1):
        """ parameter "mode" : 0 - reading file, 1 - real-time sniff"""
        global iface_to_sniff, filter_to_sniff
        self.ui.hexdump_edit.setText('Нажмите на строку, чтобы увидеть шестнадцатеричное представление пакета')
        self.ui.what_iface_sniff.setText(iface_to_sniff)
        if not self.second_thread.running:
            self.second_thread.running = True
            self.second_thread.my_sniffer.processing = True
        self.second_thread.start()
        # print('mode in start_sniff = ', mode)
        # self.second_thread.run(mode=1)

    def stop_sniff(self):
        # print('нажатие на стоп')
        self.second_thread.running = False
        self.second_thread.my_sniffer.stop_sniff()

    def closeEvent(self, event, mode=0):
        reply = QMessageBox.question \
            (self, 'Выход из приложения',
             "Сохранить перехваченные пакеты?",
             QMessageBox.No,
             QMessageBox.Yes)

        if reply == QMessageBox.Yes:
            fname = QtWidgets.QFileDialog.getSaveFileName(self, 'Open file', '/packets', 'PCAP файл (*.pcapng)')[0]
            filename = ''
            # print(platform.system())
            if platform.system() == 'Windows':
                filename = '\sniffed'
            elif platform.system() == 'Linux' or 'Darwin':
                filename = '/sniffed'
            current_dir = os.path.dirname(os.path.abspath(__file__)) + filename
            move_file(current_dir, fname)
            root_window.close()
            event.accept()

        else:
            os.remove('sniffed')
            event.accept()


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
        root_window.hide()
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

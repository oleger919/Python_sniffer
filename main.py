import scapy.all as scapy
from PyQt5.QtWidgets import QMessageBox

import mainwindownew as mainwindow
import second_window as second_window
import sys
import psutil
from PyQt5 import QtWidgets

# import darktheme
# from darktheme.widget_template import DarkPalette
# app.setPalette(DarkPalette())


class Sniff:

    def __init__(self):
        _bpf_filter_args = []

    def process_sniffed(self, packet):
        print(packet)

    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_sniffed, filter="ip")

    # sniff('Беспроводная сеть')


class Window_2(QtWidgets.QWidget, second_window.Ui_Dialog):
    def __init__(self, parent=None):
        super(Window_2, self).__init__(parent)
        self.sniff_running = False
        ui1 = mainwindow.Ui_mainWindow()
        ui1.setupUi(self)
        print(ui1.comboBox_2.currentText())
        uic = second_window.Ui_Dialog()
        uic.setupUi(self)
        uic.start_button.clicked.connect(self.start_sniff)
        uic.stop_button.clicked.connect(self.stop_sniff)

    def start_sniff(self):
        print('нажатие на старт')
        sniffer = Sniff()
        # interface = self.ui.comboBox_1.currentText()
        interface = Main.uic.comboBox_2.currentText()
        print(interface)
        self.sniff_running = True
        while self.sniff_running:
            Sniff.sniff(sniffer, interface)

    def stop_sniff(self):
        print('нажатие на стоп')
        self.sniff_running = False

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
        self.inst = Window_2()
        self.inst.show()


    # def start_sniff(self):
    #     print('нажатие на старт')
    #     sniffer = Sniff()
    #     interface = self.ui.comboBox_1.currentText()
    #     print(interface)
    #     self.sniff_running = True
    #     while self.sniff_running:
    #         Sniff.sniff(sniffer, interface)
    #
    #     # sys.exit(app.exec_())
    #
    # def stop_sniff(self):
    #     self.sniff_running = False

    def cmbbox_2_onchange(self):
        pass
        # Отслеживание изменения ComboBox_2 и TODO активация ввода параметра вручную
        # print('запуск')
        # print(str(self.comboBox_2.currentText()))
        # if self.ui.comboBox_2.currentText() == 'Ввести вручную':
        #     self.ui.lineEdit.show()

    def check_net_addrs(self):
        # Просмотр доступных сетевых интерфейсов и добавление списка в ComboBox_1
        addrs = psutil.net_if_addrs()
        # print(addrs.keys())
        self.ui.comboBox_1.addItems(addrs)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = Main()
    w.show()
    sys.exit(app.exec_())

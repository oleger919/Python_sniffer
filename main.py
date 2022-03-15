import scapy.all as scapy
import mainwindow
import window2
import sys
import psutil

# import darktheme
# from darktheme.widget_template import DarkPalette
# app.setPalette(DarkPalette())

app = mainwindow.QtWidgets.QApplication(sys.argv)
MainWindow = mainwindow.QtWidgets.QMainWindow()
ui = mainwindow.Ui_mainWindow()
ui.setupUi(MainWindow)

window2 = window2.QtWidgets.QDialog()
ui2 = window2.Ui_Dialog()
ui2.setupUi(window2)


class Sniff:

    def __init__(self):
        _bpf_filter_args = []

    def process_sniffed(self, packet):
        print(packet)

    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_sniffed, filter="ip")

    # sniff('Беспроводная сеть')


class DecorateGui:

    def __init__(self):
        ui.pushButton.clicked.connect(DecorateGui.btn1_click)
        ui.comboBox_2.currentTextChanged.connect(DecorateGui.cmbbox_2_onchange)
        self.check_net_addrs()

    def btn1_click(self):
        sniffer = Sniff()
        # print('нажатие btn1')
        # Sniff.sniff(sniffer, 'Беспроводная сеть')
        MainWindow.hide()
        window2.show()
        sys.exit(app.exec_())

    def cmbbox_2_onchange(self):
        # Отслеживание изменения ComboBox_2 и TODO активация ввода параметра вручную
        if ui.comboBox_2.currentText() == 'Ввести вручную':
            pass

    def check_net_addrs(self):
        # Просмотр доступных сетевых интерфейсов и добавление списка в ComboBox_1
        addrs = psutil.net_if_addrs()
        # print(addrs.keys())
        ui.comboBox_1.addItems(addrs)


if __name__ == "__main__":
    Start_changes = DecorateGui()
    MainWindow.show()
    sys.exit(app.exec_())

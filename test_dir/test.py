# import psutil
#
# addrs = psutil.net_if_addrs()
# print(addrs.keys())
#
# if __name__ == "__main__":
#     app = QtWidgets.QApplication(sys.argv)
#     MainWindow = QtWidgets.QMainWindow()
#     ui = Ui_MainWindow()
#     ui.setupUi(MainWindow)
#     MainWindow.show()
#     sys.exit(app.exec_())
import scapy.all as scapy


class Sniff:

    def __init__(self):
        _bpf_filter_args = []

    def process_sniffed(self, packet):
        print(packet)

    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_sniffed, filter="ip")

sn = Sniff()
Sniff.sniff(sn, 'Беспроводная сеть')

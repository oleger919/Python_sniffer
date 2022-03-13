import scapy.all as scapy

_bpf_filter_args = []

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed, filter="tcp")


def process_sniffed(packet):
    print(packet)


sniff('Беспроводная сеть')

from grader.tcputils import calc_checksum
from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.identification = 0
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        MASKSIZE = 32

        for entrada in self.tabela:
            net = struct.unpack('!I', str2addr(entrada[0].split('/')[0]))[0]
            offset = int(entrada[0].split('/')[1])
            dest_addr_number = struct.unpack('!I', str2addr(dest_addr))[0]
            MASK = (0xffffffff << (MASKSIZE - offset))
            if (net & MASK) == (dest_addr_number & MASK): 
                return entrada[1]


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela
        return
    
    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        # datagrama = IP + SEGMENTO
        # construir o header IP e no final concatenar com segmento

        # https://en.wikipedia.org/wiki/IPv4#Header

        # Algo nesse sentido, tem q arrumar algumas coisas ainda
        checksum = 0
        protocol = 6
        ttl = 64
        flags = 0x0
        frag_offset = 0x0
        total_len = 20 + len(segmento)
        ecn = 0x0
        dcsp = 0x0 
        version = 0x4
        ihl = 0x5
        self.identification += 1

        ip_header = struct.pack('!BBHHHBBH', version, ihl, dcsp, ecn, total_len, self.identification, flags, \
            frag_offset, ttl, protocol, checksum, self.meu_endereco, dest_addr)
        ip_header += self.meu_endereco + dest_addr

        checksum = calc_checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH', version, ihl, dcsp, ecn, total_len, self.identification, flags, \
            frag_offset, ttl, protocol, checksum)
        ip_header += self.meu_endereco + dest_addr


        datagrama = ip_header + segmento
        self.enlace.enviar(datagrama, next_hop)

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
            ttl -= 1
            if ttl > 0:
                version = 4
                ihl = 5
                dcspecn = (dscp << 2) + (ecn)
                flagsfrev = (flags << 13) + (frag_offset)
                vihl = (version << 4) + (ihl)
                src, = struct.unpack('!I', str2addr(src_addr))
                dest, = struct.unpack('!I', str2addr(dst_addr))
                checksum = 0
                total_length = 20 + len(payload)
                datagrama = self.make_header(vihl, dcspecn, total_length, identification, \
                    flagsfrev, ttl, proto, checksum, src, dest)
                self.enlace.enviar(datagrama, next_hop)
            else:
                next_hop = self._next_hop(src_addr)
                ttl = 64
                msg_type = 11
                code = 0
                checksum = 0
                msg = datagrama[:28]
                icmp_header = struct.pack('!BBHI', msg_type, code, checksum, 0)
                icmp_header += msg
                checksum = calc_checksum(icmp_header)
                icmp_header = struct.pack('!BBHI', msg_type, code, checksum, 0)
                icmp_header += msg
                version = 4
                ihl = 5
                dcspecn = (dscp << 2) + (ecn)
                flagsfrev = (flags << 13) + (frag_offset)
                vihl = (version << 4) + (ihl)
                src, = struct.unpack('!I', str2addr(src_addr))
                dest, = struct.unpack('!I', str2addr(self.meu_endereco))
                proto = 1
                checksum = 0
                total_length = 20 + len(icmp_header)
                ip_header = self.make_header(vihl, dcspecn, total_length, identification, \
                    flagsfrev, ttl, proto, checksum, dest, src)
                datagrama = ip_header + icmp_header
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        MASKSIZE = 32
        biggest_offset = -1
        next_hop = None

        for entrada in self.tabela:
            net = struct.unpack('!I', str2addr(entrada[0].split('/')[0]))[0]
            offset = int(entrada[0].split('/')[1])
            dest_addr_number = struct.unpack('!I', str2addr(dest_addr))[0]
            MASK = (0xffffffff << (MASKSIZE - offset))
            if (net & MASK) == (dest_addr_number & MASK) and offset > biggest_offset: 
                next_hop, biggest_offset = entrada[1], offset

        if biggest_offset > -1:
            return next_hop

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

        # Valores esperados pelo cabeçalho do protocolo
        #################################
        # Version tem 4 bits e Ihl tb
        version = 4
        ihl = 5
        vihl = (version << 4) + (ihl)
        #################################
        # DCSP tem 6 bits e ecn 2 bits.
        dcsp = 0 
        ecn = 0
        dcspecn = (dcsp << 2) + (ecn)
        #################################
        total_len = 20 + len(segmento)
        #################################
        self.identification += 1
        #################################
        # Flags tem 3 bits e flag offset 13
        flags = 0
        frag_offset = 0
        flagsfrev = (flags << 13) + (frag_offset)
        #################################
        ttl = 64
        #################################
        protocol = 6
        #################################
        # Checksum no início vale 0
        checksum = 0

        src, = struct.unpack('!I', str2addr(self.meu_endereco))
        dest, = struct.unpack('!I', str2addr(dest_addr))
        ip_header = self.make_header(vihl, dcspecn, total_len, self.identification, \
            flagsfrev, ttl, protocol, checksum, src, dest)
        # print('CAVALO',ip_header, self.meu_endereco)
        # ip_header += self.meu_endereco + dest_addr

        datagrama = ip_header + segmento
        self.enlace.enviar(datagrama, next_hop)

    def make_header(self, vihl, dcspecn, total_len, identification, \
            flagsfrev, ttl, protocol, checksum, src, dest):
        ip_header = struct.pack('!BBHHHBBHII', vihl, dcspecn, total_len, identification, \
            flagsfrev, ttl, protocol, checksum, src, dest)
        checksum = calc_checksum(ip_header)
        return struct.pack('!BBHHHBBHII', vihl, dcspecn, total_len, identification, \
            flagsfrev, ttl, protocol, checksum, src, dest)

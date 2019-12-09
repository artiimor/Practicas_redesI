from ip import *
import struct
import logging

from ip import registerIPProtocol, sendIPDatagram

UDP_HLEN = 8
UDP_PROTO = 17

'''
    Nombre: getUDPSourcePort
    Descripción: Esta función obtiene un puerto origen libre en la máquina actual.
    Argumentos:
        -Ninguno
    Retorno: Entero de 16 bits con el número de puerto origen disponible

'''
def getUDPSourcePort():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portNum =  s.getsockname()[1]
    s.close()
    return portNum


'''
    Nombre: process_UDP_datagram
    Descripción: Esta función procesa un datagrama UDP. Esta función se ejecutará por cada datagrama IP que contenga
    un 17 en el campo protocolo de IP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Extraer los campos de la cabecera UDP
        -Loggear (usando logging.debug) los siguientes campos:
            -Puerto origen
            -Puerto destino
            -Datos contenidos en el datagrama UDP

    Argumentos:
        -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
        -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
        -data: array de bytes con el conenido del datagrama UDP
        -srcIP: dirección IP que ha enviado el datagrama actual.
    Retorno: Ninguno

'''
def process_UDP_datagram(us,header,data,srcIP):
    '''
        Source_port: 2 primeros bytes
        Destination_port: bytes 3 y 4
        lenght: bytes 5 y 6
        checksum: bytes 7 y 8
    '''
    source_port = data[0:2]
    destination_port = data[2:4]
    lenght = data[4:6]
    checksum = data[6:8]

    logging.debug("Puerto origen:: " + str(source_port[0]) + "." + str(source_port[1]))
    logging.debug("Puerto destino: " + str(destination_port[0]) + "." + str(destination_port[1]))
    logging.debug("informacion del paquete: " + str(data[8:(struct.unpack('!h',lenght)[0])]))
    logging.debug("datagrama udp: " + str(data[:(struct.unpack('!h',lenght)[0])]))

    return


'''
    Nombre: sendUDPDatagram
    Descripción: Esta función construye un datagrama UDP y lo envía
     Esta función debe realizar, al menos, las siguientes tareas:
        -Construir la cabecera UDP:
            -El puerto origen lo obtendremos llamando a getUDPSourcePort
            -El valor de checksum lo pondremos siempre a 0
        -Añadir los datos
        -Enviar el datagrama resultante llamando a sendIPDatagram

    Argumentos:
        -data: array de bytes con los datos a incluir como payload en el datagrama UDP
        -dstPort: entero de 16 bits que indica el número de puerto destino a usar
        -dstIP: entero de 32 bits con la IP destino del datagrama UDP
    Retorno: True o False en función de si se ha enviado el datagrama correctamente o no

'''
def sendUDPDatagram(data,dstPort,dstIP):
    # header = bytearray(UDP_HLEN)
    
    
    # header[0:2] = struct.pack('!I', getUDPSourcePort())
    # header[2:4] = struct.pack('!I', dstPort)
    # header[4:6] = struct.pack('!I',UDP_HLEN+len(data))[-2:]  # longitud de la cabecera + longidud de los datos
    # header[6:8] = bytes((0))
    header = bytes()
    header = getUDPSourcePort().to_bytes(2, byteorder='big') + dstPort.to_bytes(2, byteorder='big') + (UDP_HLEN + len(data)).to_bytes(2, byteorder='big') + (0).to_bytes(2, byteorder='big')

    datagram = bytes()
    datagram += header
    datagram += data

    # print("\n\n\n")
    # print(header)
    # print(data)
    # print(datagram)
    # print("\n\n\n")
    sendIPDatagram(dstIP,datagram,17) # protocol = 17 porque es UDP

    return

'''
    Nombre: initUDP
    Descripción: Esta función inicializa el nivel UDP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Registrar (llamando a registerIPProtocol) la función process_UDP_datagram con el valor de protocolo 17

    Argumentos:
        -Ninguno
    Retorno: Ninguno

'''
def initUDP():
    registerIPProtocol(process_UDP_datagram, 17)
    return

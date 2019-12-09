import time

from ip import *
from threading import Lock
import struct
import logging


from ip import registerIPProtocol, chksum, sendIPDatagram

ICMP_PROTO = 1


ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}

'''
    Nombre: process_ICMP_message
    Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
    un 1 en el campo protocolo de IP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Calcular el checksum de ICMP:
            -Si es distinto de 0 el checksum es incorrecto y se deja de procesar el mensaje
        -Extraer campos tipo y código de la cabecera ICMP
        -Loggear (con logging.debug) el valor de tipo y código
        -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
            -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
            los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
            -Enviar el mensaje usando la función sendICMPMessage
        -Si el tipo es ICMP_ECHO_REPLY_TYPE:
            -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
            contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
            -Se debe proteger el acceso al diccionario de tiempos usando la vaionario de triable timeLock
            -Mostrar por pantalla la resta. Este valor será una estimación del RTT
        -Si es otro tipo:
            -No hacer nada

    Argumentos:
        -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
        -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
        -data: array de bytes con el conenido del mensaje ICMP
        -srcIP: dirección IP que ha enviado el datagrama actual.
    Retorno: Ninguno

'''
def process_ICMP_message(us,header,data,srcIp):
    # if chksum(data) != 0:
    #    logging.debug("[ERROR] process_ICMP_message ha calculado un checksum distinto de 0")
    #    return

    tipo = data[0]
    codigo = data[1]

    logging.debug("Tipo: "+str(tipo))
    logging.debug("Codigo: " + str(codigo))

    if tipo == ICMP_ECHO_REQUEST_TYPE:
        # Enviamos un reply
        # print("header: "+str(header))
        # print("data: "+str(data))
        # print("TIPO: "+str(data[0]))
        # print("del 4 al 6: "+str(data[4])+" "+str(data[5]))
        # print("del 4 al 6: ")
        # print(struct.unpack('!h',data[4:6])[0])
        # print("del 6 al 8: "+str(data[6])+" "+str(data[7]))
        # print(struct.unpack('!h',data[6:8])[0])
        # print("DESTINO: ")
        # print(struct.unpack('!I',srcIp))
        # print((struct.unpack('!I',srcIp)[0]).to_bytes(4, byteorder='big'))
        sendICMPMessage(data,ICMP_ECHO_REPLY_TYPE,0,struct.unpack('!h',data[4:6])[0],struct.unpack('!h',data[6:8])[0],struct.unpack('!I',srcIp)[0])

    elif tipo == ICMP_ECHO_REPLY_TYPE:
        with timeLock:
        	# print("\n\n\nCOSAS SUMADAS PARA EL DICCIONARIO puto again FUCCCC: ")
        	# print(struct.unpack('!I',srcIp)[0])
        	# print(struct.unpack('!h',data[4:6])[0])
        	# print(struct.unpack('!h',data[6:8])[0])
        	# print("\n\n\n")
        	tiempo_dict = icmp_send_times[struct.unpack('!I',srcIp)[0]+struct.unpack('!h',data[4:6])[0]+struct.unpack('!h',data[6:8])[0]]

        # print(header.ts.tv_sec)
        # print(tiempo_dict)

        tiempo_real = header.ts.tv_sec - tiempo_dict

        print("ESTIMACION DE RTT: "+str(tiempo_real))

    return


'''
    Nombre: sendICMPMessage
    Descripción: Esta función construye un mensaje ICMP y lo envía.
    Esta función debe realizar, al menos, las siguientes tareas:
        -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
            -Construir la cabecera ICMP
            -Añadir los datos al mensaje ICMP
            -Calcular el checksum y añadirlo al mensaje donde corresponda
            
            -Si type es ICMP_ECHO_REQUEST_TYPE
                -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                -Se debe proteger al acceso al diccionario usando la variable timeLock
                -Llamar a sendIPDatagram para enviar el mensaje ICMP

         -Si no:
            -Tipo no soportado. Se devuelve False

    Argumentos:
        -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
        -type: valor del campo tipo de ICMP
        -code: valor del campo code de ICMP 
        -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
        -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
        -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
    Retorno: True o False en función de si se ha enviado el mensaje correctamente o no

'''
def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):

    # header[0] = type
    # header[1] = code
    # header[2:4] = checksum
    # header[4:6] = id
    # header[6:8] = icmp_seqnum

    header = bytearray()
    header += type.to_bytes(1, byteorder='big')
    header += code.to_bytes(1, byteorder='big') 
    header += b'\x00\x00' #Por defecto 0
    header += icmp_id.to_bytes(2, byteorder='big') 
    header += icmp_seqnum.to_bytes(2, byteorder='big')

    datagram = bytes()
    datagram += header
    datagram += data

    checksum = chksum(datagram)
    header[2:4] = struct.pack('!H',checksum)

    if type == ICMP_ECHO_REQUEST_TYPE:
        with timeLock:
        	# print("\n\n\nCOSAS SUMADAS PARA EL DICCIONARIO: ")
        	# print(dstIP)
        	# print(icmp_id)
        	# print(icmp_seqnum)
        	# print("\n\n\n")
        	icmp_send_times[dstIP+icmp_id+icmp_seqnum] = time.time()

    # print(datagram)

    sendIPDatagram(dstIP, datagram, 1)  # protocol = 1 porque es icmp
  
    return


'''
    Nombre: initICMP
    Descripción: Esta función inicializa el nivel ICMP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

    Argumentos:
        -Ninguno
    Retorno: Ninguno

'''
def initICMP():
    registerIPProtocol(process_ICMP_message, 1)
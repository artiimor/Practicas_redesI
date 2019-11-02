'''
    practica2.py
    Programa principal que ejecuta resoluciones ARP. En este archivo No implementaremos nada.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from ethernet import *
from arp import *
import sys
import binascii
import signal
import argparse
import struct
from argparse import RawTextHelpFormatter
import time
import logging
import socket

if __name__ == "__main__":

    global pdumper, args, handle, el, stop
    parser = argparse.ArgumentParser(description='Esta practica ejecuta resoluciones ARP. Dada una direccion IP devuelve cual es la MAC asociada en la LAN actual', formatter_class=RawTextHelpFormatter)
    parser.add_argument('--itf', dest='interface', default=False, help='Interfaz a abrir')
    parser.add_argument('--debug', dest='debug', default=False, action='store_true', help='Activar Debug messages')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s %(levelname)s]\t%(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s %(levelname)s]\t%(message)s')

    if args.interface is False:
        logging.error('No se ha especificado interfaz')
        parser.print_help()
        sys.exit(-1)

    # Inicializamos el nivel Ethernet en la interfaz especificada
    if (startEthernetLevel(args.interface) != 0):
        logging.error('Ethernet no inicializado')
        sys.exit(-1)
    # Inicializamos ARP. Si no podemos inicializar salimos.
    if initARP(args.interface) is False:
        logging.error('ARP no inicializado')
        stopEthernetLevel()
        sys.exit(-1)
    ''' Bucle infinito que leera las opciones por teclado y ejecutara las acciones correspondientes
		(resolver una direccion, imprimrir la cache o salir)
	'''
    while True:
        try:
            msg = input('Introduce la direccion IP a resolver (q para salir y p para mostrar la cache):\n')
            if msg == 'q':
                break
            elif msg == 'p':
                printCache()
            else:
                try:
                    # Convertimos la direccion IP en formato textual (X.X.X.X) a un entero de 32 bits.
                    ip = struct.unpack('!I', socket.inet_aton(msg))[0]
                    # Llamamos a la funcion de realizar resolucion ARP con la IP que hemos leido
                    ret = ARPResolution(ip)
                    # Si hay respuesta imprimir la direccion MAC
                    if ret is not None:
                        print(':'.join(['{:02X}'.format(b) for b in ret]))
                    else:
                        print('Direccion no encontrada\n')
                except OSError:
                    # Si ha fallado la conversion de IP, el formato es incorrecto.
                    print('Formato de IP incorrecta\n')
        except KeyboardInterrupt:
            print('\n')
            break
    logging.info('Cerrando ....')
    # Paramos el nivel Ethernet
    if (stopEthernetLevel() != 0):
        logging.error('Parando nivel Ethernet')
        sys.exit(-1)

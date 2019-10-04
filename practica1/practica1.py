'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from rc1_pcap import *
from datetime import datetime
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60

def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)

def procesa_paquete(us,header,data):
	global num_paquete, pdumper
	num_paquete += 1	
	#create the dumper
	if pdumper is None:
		pdumper = pcap_dump_open(handle,'captura.' + args.interface + str(header.ts.tv_sec + TIME_OFFSET))
	#TODO imprimir los N primeros bytes
	#Escribir el tráfico al fichero de captura con el offset temporal
	pcap_dump(pdumper, header, data)

	
if __name__ == "__main__":
	global pdumper,args, handle

	#Argument stuff
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	#create the SIGINT handler
	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper = None
	
	#open the interface for capture it. When its open_live we want to capture the package complete
	handle = pcap_open_live(args.interface, args.nbytes, NO_PROMISC, ETH_FRAME_MAX, errbuf)
	#check it went right
	if handle is None:
		print ("No se ha capturado nada")
		sys.exit(-1)

	
	#loop. It is interrupted when we send SIGINT, when it reads all the packages or when there's an error
	ret = pcap_loop(handle,50,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete)) #when it ends we show the number of packages
	
	#close descriptors
	if handle is not None:
		pcap_close(handle)

	if pdumper is not None:
		pcap_dump_close(pdumper)
	


# Projekt NDR/IDS na Raspberry Pi
System wykrywania i reagowania na incydenty sieciowe (Network Detection and Response).

## O Projekcie
Celem projektu jest budowa sensora monitorującego ruch sieciowy w czasie rzeczywistym. System analizuje pakiety niskopoziomowo w celu wykrywania anomalii.

## Tech Stack
* Jezyk: C++ (Sensor), Python (Analiza i Logika)
* Biblioteki: libpcap
* Sprzet: Raspberry Pi

## Struktura Projektu i wyniki testów

* **01_interface_list.cpp** - Rozpoznawanie interfejsów sieciowych.
![Lista interfejsów](media/01_interface_list.png)

* **02_protocol_sniffer.cpp** - Analiza nagłówków IP, TCP, UDP i ICMP.
![Sniffer protokołów](media/02_protocol_sniffer.png)

* **03_ping_flood_detector.cpp** - Wykrywanie ataków Ping Flood.
![Detekcja Flood](media/03_flood_detector.png)

## Analiza techniczna i wnioski
W trakcie realizacji tych etapów skupiłem się na następujących zagadnieniach:

* **Rzutowanie struktur (Pointer Casting):** Zrozumienie, w jaki sposób przesunięcie wskaźnika o 14 bajtów (rozmiar nagłówka Ethernet) pozwala na bezpośrednie mapowanie surowych danych z bufora na strukturę `iphdr`. Pozwala to na uniknięcie kosztownego kopiowania danych.
* **Analiza warstwy transportowej:** Implementacja rozpoznawania protokołów TCP, UDP oraz ICMP na podstawie pola `protocol` w nagłówku IP.
* **Detekcja anomalii:** Opracowanie algorytmu zliczającego pakiety w oknie czasowym (1 sekunda) w celu identyfikacji ataków typu Flood.

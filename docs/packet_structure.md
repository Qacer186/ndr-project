# Analiza struktury pakietu (Pociąg bajtów)

W bibliotece libpcap pakiet jest dostarczany jako ciągły strumień bajtów w pamięci RAM.

### Offset i rzutowanie
1. **Nagłówek Ethernet (14 bajtów):** Każda ramka zaczyna się od 14 bajtów danych warstwy drugiej (adresy MAC i typ). 
2. **Nagłówek IP:** Wiemy, że dane IP zaczynają się dokładnie po nagłówku Ethernet. Dlatego przesuwamy wskaźnik o 14 bajtów: `packet + 14`.
3. **Mapowanie:** Zamiast ręcznie wyliczać pozycję każdego pola (np. adresu IP), rzutujemy ten adres na strukturę systemową: 
   `(struct iphdr *)(packet + 14)`.

Dzięki temu kompilator wie, że np. pole `ip->protocol` znajduje się dokładnie 9 bajtów od początku nagłówka IP. Jest to najszybsza metoda analizy, ponieważ nie wymaga kopiowania danych, a jedynie nakłada "szablon" na istniejące bajty w pamięci.

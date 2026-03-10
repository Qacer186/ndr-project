#include <iostream>
#include <pcap.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    // Pobieramy listę dostępnych urządzeń sieciowych
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Błąd przy wyszukiwaniu urządzeń: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Znalezione interfejsy sieciowe:" << std::endl;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        std::cout << "- " << d->name;
        if (d->description) std::cout << " (" << d->description << ")";
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
    return 0;
}

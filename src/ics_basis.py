# -- Coding: utf-8 --
# @Version: 1.0.0
# @Time: 2024/11/22 16:41

ics_ports = {
    102: "s7comm",
    502: "modbus/tcp",
    503: "modbus/tcp",
    44818: "ethernet/ip",
}

ics_protocol_ports = {
    "s7": [102],
    "modbus": [502, 503],
    "enip": [44818]
}

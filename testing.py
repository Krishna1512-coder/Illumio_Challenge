import unittest
from Firewall import Firewall
class TestFirewall(unittest.TestCase):

    def setUp(self):
        test_file = open("test_file.csv", "w")
        test_file.write("inbound,tcp,80,192.168.1.2\n")
        test_file.write("outbound,tcp,1-65535,192.168.10.11\n")
        test_file.write("inbound,udp,53,0.0.0.0-255.255.255.255\n")
        test_file.write("inbound,udp,10-15,192.170.1.1-192.170.2.5\n")
        test_file.close()

    def test_accept_packet_1(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","tcp",80,"192.168.1.2"))
    
    def test_accept_packet_2(self):
        firewall = Firewall("test_file.csv")
        self.assertFalse(firewall.accept_packet("inbound","tcp",80,"192.168.1.1"))
        
    def test_accept_packet_3(self):
        firewall = Firewall("test_file.csv")
        self.assertFalse(firewall.accept_packet("inbound","tcp",80,"192.168.1.3"))



    def test_accept_packet_4(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("outbound","tcp",1,"192.168.10.11"))
    
    def test_accept_packet_5(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("outbound","tcp",65535,"192.168.10.11"))

    def test_accept_packet_6(self):
        firewall = Firewall("test_file.csv")
        self.assertFalse(firewall.accept_packet("inbound","tcp",65535,"192.168.10.11"))
        
    def test_accept_packet_7(self):
        firewall = Firewall("test_file.csv")
        self.assertFalse(firewall.accept_packet("outbound","tcp",80,"192.168.1.3"))



    def test_accept_packet_8(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","udp",53,"0.0.0.0"))
    
    def test_accept_packet_9(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","udp",53,"255.255.255.255"))

    def test_accept_packet_10(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","udp",53,"161.158.0.10"))    
    
    def test_accept_packet_11(self):
        firewall = Firewall("test_file.csv")
        self.assertFalse(firewall.accept_packet("inbound","udp",51,"255.255.255.255"))



    def test_accept_packet_12(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","udp",10,"192.170.1.1"))

    def test_accept_packet_13(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","udp",15,"192.170.1.1"))
    
    def test_accept_packet_14(self):
        firewall = Firewall("test_file.csv")
        self.assertFalse(firewall.accept_packet("inbound","udp",16,"192.170.1.1"))    

    def test_accept_packet_15(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","udp",12,"192.170.1.1"))
    
    def test_accept_packet_16(self):
        firewall = Firewall("test_file.csv")
        self.assertTrue(firewall.accept_packet("inbound","udp",13,"192.170.2.5"))

    def test_accept_packet_17(self):
        firewall = Firewall("test_file.csv")
        self.assertFalse(firewall.accept_packet("inbound","udp",13,"192.170.2.6"))

  
if __name__ == '__main__': 
    unittest.main()

"""
Tests for the core module
"""
import pytest
import socket
from unittest.mock import patch, MagicMock
from mailoney.core import SMTPHoneypot

@pytest.fixture
def smtp_honeypot():
    """Test SMTP honeypot fixture"""
    honeypot = SMTPHoneypot(
        bind_ip="127.0.0.1",
        bind_port=8025,
        server_name="test.example.com"
    )
    return honeypot

def test_smtp_honeypot_init(smtp_honeypot):
    """Test SMTP honeypot initialization"""
    assert smtp_honeypot.bind_ip == "127.0.0.1"
    assert smtp_honeypot.bind_port == 8025
    assert smtp_honeypot.server_name == "test.example.com"
    assert "test.example.com" in smtp_honeypot.ehlo_response
    assert smtp_honeypot.socket is None

@patch("socket.socket")
def test_smtp_honeypot_start(mock_socket, smtp_honeypot):
    """Test SMTP honeypot start method"""
    # Setup mock socket
    mock_socket_instance = MagicMock()
    mock_socket.return_value = mock_socket_instance
    
    # Create a flag to check if _accept_connections was called
    was_called = [False]
    original_accept = smtp_honeypot._accept_connections
    
    # Create a wrapper function that sets the flag
    def accept_wrapper(*args, **kwargs):
        was_called[0] = True
        return None
    
    # Patch _accept_connections to avoid infinite loop and check if called
    with patch.object(smtp_honeypot, "_accept_connections", side_effect=accept_wrapper):
        smtp_honeypot.start()
        
    # Verify socket configuration
    mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_socket_instance.setsockopt.assert_called_with(
        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
    )
    mock_socket_instance.bind.assert_called_with(("127.0.0.1", 8025))
    mock_socket_instance.listen.assert_called_with(10)
    
    # Verify _accept_connections was called using our own flag
    assert was_called[0] == True, "_accept_connections method was not called"

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
    
    # Create a simple counter to check if the method was called
    call_count = [0]
    
    # Define a replacement function that increments the counter
    def accept_connections_mock():
        call_count[0] += 1
        return None
    
    # Replace the method with our mock that increments the counter
    original_method = smtp_honeypot._accept_connections
    smtp_honeypot._accept_connections = accept_connections_mock
    
    try:
        # Call the start method
        smtp_honeypot.start()
        
        # Verify socket configuration
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket_instance.setsockopt.assert_called_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        mock_socket_instance.bind.assert_called_with(("127.0.0.1", 8025))
        mock_socket_instance.listen.assert_called_with(10)
        
        # Verify our function was called
        assert call_count[0] > 0, "The _accept_connections method was not called"
    finally:
        # Restore the original method
        smtp_honeypot._accept_connections = original_method

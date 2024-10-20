import datetime
import os
import pytest
import aiofiles
import aiohttp
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from modules.ip_gathering import IPGatherer


@pytest.fixture
def ip_gatherer():
    """Fixture to initialize the IPGatherer."""
    return IPGatherer()


@pytest.mark.asyncio
async def test_ip_history_viewdnsinfo_success(ip_gatherer):
    """Test successful IP extraction from viewdns.info."""
    domain = "example.com"
    mock_html = """
    <table border="1">
        <tr><td>IP Address</td><td>Location</td></tr>
        <tr><td>192.168.1.1</td><td>Location 1</td></tr>
        <tr><td>10.0.0.1</td><td>Location 2</td></tr>
    </table>
    """

    # Mocking the aiohttp ClientSession
    with patch("aiohttp.ClientSession", new_callable=AsyncMock) as mock_session:
        # Create an AsyncMock for the response
        mock_response = AsyncMock()
        mock_response.text.return_value = mock_html

        # Mock the context manager's __aenter__ and __aexit__
        mock_session.return_value.__aenter__.return_value = mock_response

        # Mock the get method to return the mock response
        mock_response.__aenter__.return_value = mock_response
        mock_response.__aexit__.return_value = False  # not raising any exception

        # Call the method being tested
        ips = await ip_gatherer._ip_history_viewdnsinfo(domain)

        # Check the result
        assert ips == {"192.168.1.1", "10.0.0.1"}
        mock_session.return_value.__aenter__.return_value.get.assert_called_once_with(
            f"https://viewdns.info/iphistory/?domain={domain}", timeout=30)


@pytest.mark.asyncio
async def test_ip_history_viewdnsinfo_limit_exceeded(ip_gatherer):
    """Test viewdns.info daily limit exceeded scenario."""
    domain = "example.com"
    limit_exceeded_html = "403 Forbidden - Naughty!"
    with patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
        mock_resp = AsyncMock()
        mock_resp.text = AsyncMock(return_value=limit_exceeded_html)
        mock_get.return_value = mock_resp
        result = await ip_gatherer._ip_history_viewdnsinfo(domain)
        assert result == -403
        mock_get.assert_called_once_with(f"https://viewdns.info/iphistory/?domain={domain}", timeout=30)


@pytest.mark.asyncio
async def test_remove_original_ips(ip_gatherer):
    """Test removing original DNS resolved IPs."""
    domain = "example.com"
    original_ips = {"192.168.1.1", "10.0.0.1", "8.8.8.8"}
    with patch("dns.resolver.resolve") as mock_resolve:
        # Mock DNS resolution
        mock_resolve.return_value = [MagicMock(to_text=lambda: "8.8.8.8")]
        filtered_ips = await ip_gatherer._remove_original_ips(domain, original_ips)
        assert filtered_ips == {"192.168.1.1", "10.0.0.1"}


@pytest.mark.asyncio
async def test_write_html_response(ip_gatherer):
    """Test writing HTML response to a file."""
    domain = "example.com"
    response_text = "<html>Some response</html>"
    sanitized_domain = ip_gatherer.sanitize_filename(domain)
    file_path = os.path.normpath(os.path.join(ip_gatherer.log_dir,
                                              f'{sanitized_domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}_HTML.txt'))

    # Mock aiofiles.open to behave as an async context manager
    mock_file = AsyncMock()  # Mock for the file object
    mock_open = AsyncMock(return_value=mock_file)  # Mock for aiofiles.open

    # Setup the return value of __aenter__ and __aexit__ for the mock_open
    mock_open.return_value.__aenter__.return_value = mock_file
    mock_open.return_value.__aexit__.return_value = False  # Mock __aexit__

    with patch("aiofiles.open", mock_open):
        await ip_gatherer._write_html_response(domain, response_text)

        # Assertions to verify correct behavior
        mock_open.assert_called_once_with(file_path, 'w')
        await mock_file.write.assert_awaited_once_with(response_text)  # Ensure the write was called correctly


@pytest.mark.asyncio
async def test_write_extracted_ips_to_file(ip_gatherer, tmpdir):
    """Test writing extracted IPs to a file."""
    domain = "example.com"
    ips = {"192.168.1.1", "10.0.0.1"}
    ip_gatherer.log_dir = tmpdir
    with patch("aiofiles.open", new_callable=AsyncMock) as mock_open:
        mock_file = AsyncMock()
        mock_open.return_value = mock_file
        await ip_gatherer._write_extracted_ips_to_file(domain, ips)
        mock_open.assert_called_once()


@pytest.mark.asyncio
async def test_sanitize_filename(ip_gatherer):
    """Test sanitizing domain for filenames."""
    domain = "example.com/with_special#chars!"
    sanitized = ip_gatherer.sanitize_filename(domain)
    assert sanitized == "example.comwithspecialchars"

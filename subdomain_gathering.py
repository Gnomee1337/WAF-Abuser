import asyncio
import aiohttp
import datetime
import os

import tldextract
from bs4 import BeautifulSoup


# async def dnsdumpster_scraping(domains: list[str]):
async def dnsdumpster_scraping(domains: list[str]):
    dnsdumpster_output = []
    CSRFtoken = ''

    if not os.path.isdir(os.getcwd() + '/cache/dnsdumpster_req_logs'):
        os.mkdir(os.getcwd() + '/cache/dnsdumpster_req_logs')

    for domain in domains:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as session:
            #async with session.get('https://dnsdumpster.com') as resp:
            #    cookies = session.cookie_jar.filter_cookies('https://dnsdumpster.com')
            #    # print(cookies.items())
            #    # print(str(cookies.get('csrftoken')).split('Set-Cookie: csrftoken='))
            #    CSRFtoken = str(cookies.get('csrftoken')).split('Set-Cookie: csrftoken=')[1]
            #    # print('CSRFTOKEN: ' + CSRFtoken)
            #async with session.post('https://dnsdumpster.com',
            #                        # data=f'csrfmiddlewaretoken={CSRFtoken}&targetip={domain}&user=free)',
            #                        data={'csrfmiddlewaretoken': CSRFtoken,
            #                              'targetip': domain,
            #                              'user': 'free'},
            #                        headers={'Host': 'dnsdumpster.com',
            #                                 'Pragma': 'no-cache',
            #                                 'Cache-Control': 'no-cache',
            #                                 'Upgrade-Insecure-Requests': '1',
            #                                 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            #                                 'Origin': 'https://dnsdumpster.com',
            #                                 'Content-Type': 'application/x-www-form-urlencoded',
            #                                 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            #                                 'Referer': 'https://dnsdumpster.com/',
            #                                 'Accept-Language': 'en-US,en;q=0.9,nl;q=0.8',
            #                                 'Cookie': f'csrftoken={CSRFtoken}'}
            #                        ) as resp:
                #with open(os.path.join(os.getcwd() + '/cache/dnsdumpster_req_logs',
                #                       f'{domain}_{datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")}.txt'),
                #          'a') as post_request_file:
                #    post_request_file.write(await resp.text())
                with open(os.getcwd() + '/cache/dnsdumpster_req_logs/facebook.com_23-01-2024_09h22m49s.txt','r') as post_req:
                    text = post_req.read()

                #print(text)
                #text = await resp.read()
                soup = BeautifulSoup(text.encode('utf-8'),'html.parser')
                rb = soup.find_all('td',{'class':'col-md-4'})
                # txt = []
                # for i in soup.find_all('a',{'class':'external nounderline','data-toggle':'modal'},href=True):
                #     txt.append(i.href.strip().replace('n',''))
                #     # if i.nextSibling == u'br':
                #     #     txt.append(i.nextSibling.text.strip().replace('n',''))
                # print(txt)
                for found_domain in rb:
                   dnsdumpster_output.append(found_domain.text.replace('\n','').split('HTTP: ')[0].replace('. ',''))
                print(dnsdumpster_output)
                # CSRFtoken=cookies.s
                # for key, cookie in cookies.items():
                #    print('Key: "%s", Value: "%s"' % (cookie.key, cookie.value))
                # print(resp.status)
                # print(await resp.text())


async def subdomain_gathering(domains: list[str]):
    await dnsdumpster_scraping(domains)
    pass


asyncio.run(subdomain_gathering(['stackoverflow.com']))

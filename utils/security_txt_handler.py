from sectxt import SecurityTXT
import json

class SecurityTxtHandler:
    def __init__(self, logger):
        self.logger = logger

    def check_security_txt(self, base_url):
        try:
            self.logger.info(f"Checking security.txt for {base_url}")
            s = SecurityTXT(base_url)
            for error in s.errors:
                if error.get('code') == 'invalid_media':
                    self.logger.warning(f"Invalid media type for {base_url}. Skipping.")
                    return None, None, None
                elif error.get('code') == 'no_security_txt':
                    self.logger.warning(f"No security.txt present {base_url}. Skipping.")
                    return None, None, None
            lines = json.loads(json.dumps(s.lines))
            security_txt_url = s.resolved_url

            for line in lines:
                if line.get('field_name') == 'policy':
                    self.logger.info(f"Found policy in security.txt for {base_url}")
                    return security_txt_url, line.get('value'), "security.txt"

            self.logger.info(f"No policy found in security.txt for {base_url}")
            return security_txt_url, None, "security.txt"
        except Exception as e:
            self.logger.error(f"Error processing security.txt for {base_url}: {e}")
            return None, None, None
        
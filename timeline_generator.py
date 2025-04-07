import datetime


class TimelineGenerator:
    def __init__(self, filename='attack_logs.txt'):
        self.filename = filename
        self.data = self._load_data()

    def _load_data(self):
        loaded_data = []
        try:
            with open(self.filename, 'r') as file:
                text = file.read()
            lines = text.strip().split('\n\n')
            for block in lines:
                timestamp_line = None
                description_lines = []
                for line in block.split('\n'):
                    if line.startswith('Timestamp:'):
                        timestamp_line = line.split('Timestamp:')[1].strip()
                    elif line.strip():
                        description_lines.append(line.strip())
                if timestamp_line:
                    loaded_data.append({'Timestamp': timestamp_line, 'Description': ' '.join(description_lines)})
        except FileNotFoundError:
            print(f"Error: File '{self.filename}' not found.")
            return []

        self._assign_attack_stage(loaded_data)
        return loaded_data

    def _assign_attack_stage(self, loaded_data):
        for event in loaded_data:
            description = event['Description'].lower()
            if "account failed to log on" in description or "account was successfully logged on" in description:
                event['Stage'] = 'Initial Access'
            elif "special privileges assigned" in description:
                event['Stage'] = 'Privilege Escalation'
            elif "new process has been created" in description or "scheduled task was created" in description or "service was installed" in description:
                event['Stage'] = 'Execution'
            elif "defender detected malware" in description:
                event['Stage'] = 'Defense Evasion'
            elif "filtering platform has permitted a connection" in description or "network share object was checked for access" in description:
                event['Stage'] = 'Lateral Movement'
            elif "attempt was made to access an object" in description or "handle to an object was requested" in description:
                event['Stage'] = 'Collection'
            elif "defender removed malware" in description:
                event['Stage'] = 'Impact'
            else:
                event['Stage'] = 'Unknown'

    def get_timestamps(self):
        return [datetime.datetime.strptime(item['Timestamp'], '%m/%d/%Y %I:%M:%S %p') for item in self.data]

    def get_stages(self):
        return [item['Stage'] for item in self.data]

    def get_descriptions(self):
        return [item['Description'] for item in self.data]

    def get_processed_data(self):
        return self.data


if __name__ == "__main__":
    analyzer = TimelineGenerator('attack_logs.txt')
    if analyzer.get_processed_data():
        print("First 5 processed log entries:")
        for i, entry in enumerate(analyzer.get_processed_data()[:5]):
            print(
                f"  {i + 1}. Timestamp: {entry['Timestamp']}, Stage: {entry['Stage']}, Description: {entry['Description']}")

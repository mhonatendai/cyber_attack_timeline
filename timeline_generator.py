import matplotlib.pyplot as plt
import datetime

def load_data(filename):
    data = []
    with open(filename, 'r') as file:
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
            data.append({'Timestamp': timestamp_line, 'Description': ' '.join(description_lines)})

    for event in data:
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
    return data

data = load_data('attack_logs.txt')

timestamps = [datetime.datetime.strptime(item['Timestamp'], '%m/%d/%Y %I:%M:%S %p') for item in data]
stages = [item['Stage'] for item in data]
descriptions = [item['Description'] for item in data]

plt.figure(figsize=(14, 8))
stage_colors = {
    'Initial Access': 'red',
    'Privilege Escalation': 'blue',
    'Execution': 'green',
    'Defense Evasion': 'cyan',
    'Lateral Movement': 'magenta',
    'Collection': 'yellow',
    'Impact': 'black',
    'Unknown': 'gray'
}

for i, (ts, stage, desc) in enumerate(zip(timestamps, stages, descriptions)):
    plt.plot(ts, i, marker='o', color=stage_colors[stage], markersize=8)

    plt.text(ts, i + 0.1, f"{ts.strftime('%Y-%m-%d %H:%M:%S')}: {desc}", fontsize=8, ha='left', va='center')

plt.yticks([])
plt.xlabel('Time')
plt.title('Attack Log Timeline with Stages')
plt.grid(axis='x')

legend_elements = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=8, label=stage)
                   for stage, color in stage_colors.items()]

plt.legend(handles=legend_elements, loc='upper left')

plt.tight_layout()
plt.show()
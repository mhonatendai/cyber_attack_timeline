import matplotlib
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from timeline_generator import TimelineGenerator
matplotlib.use('TkAgg')


class LogPlotter:
    def __init__(self, log_analyzer):
        if not isinstance(log_analyzer, TimelineGenerator):
            raise TypeError("log_analyzer must be an instance of LogAnalyzer")
        self.analyzer = log_analyzer
        self.stage_colors = {
            'Initial Access': 'red',
            'Privilege Escalation': 'blue',
            'Execution': 'green',
            'Defense Evasion': 'cyan',
            'Lateral Movement': 'magenta',
            'Collection': 'yellow',
            'Impact': 'black',
            'Unknown': 'gray'
        }

    def create_timeline_plot(self):
        timestamps = self.analyzer.get_timestamps()
        stages = self.analyzer.get_stages()
        descriptions = self.analyzer.get_descriptions()

        plt.figure(figsize=(14, 8))

        for i, (ts, stage, desc) in enumerate(zip(timestamps, stages, descriptions)):
            plt.plot(ts, i, marker='o', color=self.stage_colors[stage], markersize=8)
            plt.text(ts, i + 0.1, f"{ts.strftime('%Y-%m-%d %H:%M:%S')}: {desc}", fontsize=8, ha='left', va='center')

        plt.yticks([])
        plt.xlabel('Time')
        plt.title('Attack Log Timeline with Stages')
        plt.grid(axis='x')

        legend_elements = [Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=8, label=stage)
                           for stage, color in self.stage_colors.items()]

        plt.legend(handles=legend_elements, loc='upper left')

        plt.tight_layout()
        plt.show()


if __name__ == "__main__":
    analyzer = TimelineGenerator('attack_logs.txt')
    if analyzer.get_processed_data():
        plotter = LogPlotter(analyzer)
        plotter.create_timeline_plot()

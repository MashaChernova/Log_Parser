import re
import json
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
import os

@dataclass
class LogEntry:
    ip: str
    method: str
    url: str
    date: str
    duration: int


class LogParser:
    LOG_PATTERN = re.compile(
            r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
            r'\[(?P<date>.*?)\].*?'
            r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS) '
            r'(?P<url>\S+).*?" '
            r'(?P<duration>\d+)$'
        )

    def __init__(self):
        self.total_requests = 0
        self.method_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        self.slow_requests: List[LogEntry] = []

    def parse_line(self, line: str) -> LogEntry:
        match = self.LOG_PATTERN.search(line)
        if not match:
            return None
        data = match.groupdict()
        return LogEntry(
            ip=data['ip'],
            method=data['method'],
            url=data['url'],
            date=data['date'],
            duration=int(data['duration'])
        )
    def process_entry(self, entry: LogEntry):
        self.total_requests += 1
        self.method_counts[entry.method] += 1
        self.ip_counts[entry.ip] += 1
        if len(self.slow_requests) < 3 or entry.duration > self.slow_requests[-1].duration:
            self.slow_requests.append(entry)
            self.slow_requests.sort(key=lambda x: x.duration, reverse=True)
            self.slow_requests = self.slow_requests[:3]

    def analyze_file(self, file_path: str):
        """Анализирует весь лог-файл"""
        with open(file_path, 'r') as f:
            for line in f:
                entry = self.parse_line(line)
                if entry is not None:
                    self.process_entry(entry)

    def get_top_ips(self, n: int = 3) -> List[Tuple[str, int]]:
        """Возвращает топ-N IP-адресов"""
        return sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def save_results(self, output_path: str):
        """Сохраняет результаты в JSON"""
        result = {
            'total_requests': self.total_requests,
            'method_counts': dict(self.method_counts),
            'top_ips': self.get_top_ips(),
            'slow_requests': [
                {
                    'ip': entry.ip,
                    'method': entry.method,
                    'url': entry.url,
                    'date': entry.date,
                    'duration': entry.duration
                }
                for entry in self.slow_requests
            ]
        }
        print(result)
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=4)


def main():
    parser = argparse.ArgumentParser(description='Анализатор логов веб-сервера')
    parser.add_argument('input', help='Путь к лог-файлу или директории')
    parser.add_argument('-o', '--output', help='Путь для сохранения результатов')
    args = parser.parse_args()

    analyzer = LogParser()

    if os.path.isfile(args.input):
        analyzer.analyze_file(args.input)
        output_path = args.output or f'{args.input}.json'
        analyzer.save_results(output_path)
    elif os.path.isdir(args.input):
        for filename in os.listdir(args.input):
            if filename.endswith('.log'):
                file_path = os.path.join(args.input, filename)
                analyzer.analyze_file(file_path)

        output_path = args.output or 'logs_analysis.json'
        analyzer.save_results(output_path)
    else:
        print('Ошибка: указан неверный путь')
        return 1


if __name__ == '__main__':
    main()



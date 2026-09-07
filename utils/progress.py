import sys
import time

class ProgressBar:
    """Terminal-based progress bar without external dependencies."""

    def __init__(self, total: int, bar_length: int = 40, prefix: str = ""):
        """
        Initialize the ProgressBar.

        :param total: Total number of items to process.
        :param bar_length: Character width of the progress bar.
        :param prefix: Optional prefix text before the bar.
        """
        self.total = total
        self.bar_length = bar_length
        self.prefix = prefix
        self.current = 0
        self.start_time = time.time()

    def update(self, amount: int = 1):
        """Increment the progress counter and redraw the bar."""
        self.current += amount
        self._draw()

    def _draw(self):
        """Render the progress bar on the current terminal line."""
        if self.total == 0:
            return

        fraction = self.current / self.total
        filled = int(self.bar_length * fraction)
        bar = '\u2588' * filled + '\u2591' * (self.bar_length - filled)

        elapsed = time.time() - self.start_time
        percent = fraction * 100

        line = f"\r{self.prefix}[{bar}] {percent:5.1f}% ({self.current}/{self.total}) | {elapsed:.1f}s elapsed"

        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        """Complete the progress bar and move to the next line."""
        self.current = self.total
        self._draw()
        sys.stdout.write("\n")
        sys.stdout.flush()

import os
import tempfile
import unittest
from unittest.mock import Mock, patch
from src.runtime.scheduler import AudioDownloader, _PendingSpawn
from src.ai.transcriber import Transcriber


class AudioRecoveryTests(unittest.TestCase):
    def test_cancelled_pending_never_fetches_url(self):
        with tempfile.TemporaryDirectory() as directory:
            downloader = AudioDownloader(directory, max_concurrent=1)
            client = Mock()
            downloader._spawn_when_ready(client, '1', '2', _PendingSpawn())
            client.get_video_url.assert_not_called()
            self.assertTrue(downloader._sem.acquire(blocking=False))

    def test_cancel_during_url_fetch_never_spawns(self):
        with tempfile.TemporaryDirectory() as directory:
            downloader = AudioDownloader(directory, max_concurrent=1)
            pending = _PendingSpawn()
            downloader._active['2'] = pending
            client = Mock()
            def url(*args):
                downloader.release('2')
                return 'https://example.com/audio'
            client.get_video_url.side_effect = url
            client.get_stream_params.return_value = ('https://example.com/audio', '')
            with patch('src.runtime.scheduler.subprocess.Popen') as popen:
                downloader._spawn_when_ready(client, '1', '2', pending)
                popen.assert_not_called()
            self.assertEqual(os.listdir(directory), [])
            self.assertTrue(downloader._sem.acquire(blocking=False))

    def test_spawn_failure_cleans_tempfile_and_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            downloader = AudioDownloader(directory, max_concurrent=1)
            pending = _PendingSpawn()
            downloader._active['2'] = pending
            client = Mock()
            client.get_stream_params.return_value = ('https://example.com/audio', '')
            with patch('src.runtime.scheduler.subprocess.Popen', side_effect=OSError('missing')):
                downloader._spawn_when_ready(client, '1', '2', pending)
            self.assertEqual(os.listdir(directory), [])
            self.assertIsNone(downloader.get('2'))
            self.assertTrue(downloader._sem.acquire(blocking=False))

    def test_stalled_audio_exits_without_partial_result(self):
        transcriber = Transcriber()
        proc = Mock()
        proc.poll.return_value = None
        def consume(**kwargs):
            self.assertEqual(kwargs['read_fn'](64000), b'')
            kwargs['read_fn'](64000)
            self.fail('Stalled stream should raise')
        with tempfile.NamedTemporaryFile() as audio:
            with patch.object(transcriber, '_consume_pcm_stream', side_effect=consume), \
                 patch('src.ai.transcriber.time.monotonic', side_effect=[0, 121]):
                with self.assertRaisesRegex(TimeoutError, 'stalled'):
                    transcriber.transcribe_tail(audio.name, proc, [])

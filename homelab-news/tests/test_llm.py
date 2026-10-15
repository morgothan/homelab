"""Tests for the shared LLM dispatch helpers ``llm.complete`` and ``llm.generate_articles``."""

import asyncio
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import httpx
import llm


def _client_mock(response_body: dict | None = None,
                 post_result: MagicMock | None = None) -> MagicMock:
    """Return a MagicMock AsyncClient context manager whose post returns ``post_result``.

    If ``post_result`` is None, a default response MagicMock is constructed from
    ``response_body`` (200 OK with ``.json()`` = ``response_body``).
    """
    if post_result is None:
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = response_body
        post = AsyncMock(return_value=resp)
    else:
        post = post_result
    client = MagicMock()
    client.post = post
    cm = MagicMock()
    cm.__aenter__.return_value = client
    cm.__exit__ = AsyncMock(return_value=False)
    return cm


class CompleteTests(unittest.TestCase):
    def test_complete_returns_parsed_dict_on_200(self):
        payload = {"choices": [{"message": {"content": "hello"}}]}
        cm = _client_mock(response_body=payload)
        with patch.object(llm.httpx, "AsyncClient", return_value=cm) as ac:
            result = asyncio.run(llm.complete(
                [{"role": "user", "content": "hi"}],
                max_tokens=10, temperature=0.1, url="http://model", model="m",
            ))
        self.assertEqual(result, payload)
        self.assertEqual(ac.call_args.kwargs["timeout"], llm.OLLAMA_TIMEOUT)
        url = cm.__aenter__.return_value.post.call_args.args[0]
        self.assertEqual(url, "http://model/v1/chat/completions")
        body = cm.__aenter__.return_value.post.call_args.kwargs["json"]
        self.assertEqual(body["model"], "m")
        self.assertEqual(body["messages"], [{"role": "user", "content": "hi"}])
        self.assertIs(body["stream"], False)
        self.assertEqual(body["max_tokens"], 10)
        self.assertEqual(body["temperature"], 0.1)
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})

    def test_complete_returns_none_on_connect_error(self):
        post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        cm = _client_mock(post_result=post)
        with patch.object(llm.httpx, "AsyncClient", return_value=cm):
            result = asyncio.run(llm.complete(
                [{"role": "user", "content": "hi"}],
                max_tokens=10, temperature=0.1, url="http://model", model="m",
            ))
        self.assertIsNone(result)

    def test_complete_returns_none_on_http_error_status(self):
        request = httpx.Request("POST", "http://model/v1/chat/completions")
        response = httpx.Response(500, request=request)
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server error", request=request, response=response,
        )
        post = AsyncMock(return_value=resp)
        cm = _client_mock(post_result=post)
        with patch.object(llm.httpx, "AsyncClient", return_value=cm):
            result = asyncio.run(llm.complete(
                [{"role": "user", "content": "hi"}],
                max_tokens=10, temperature=0.1, url="http://model", model="m",
            ))
        resp.raise_for_status.assert_called_once()
        self.assertIsNone(result)


class GenerateArticlesTests(unittest.TestCase):
    def test_generate_articles_returns_none_on_nondict_output(self):
        with patch.object(llm, "complete", AsyncMock(return_value=None)):
            result = asyncio.run(llm.generate_articles(
                [{"role": "user", "content": "x"}],
                max_tokens=5, temperature=0.1, max_count=4, url="http://model", model="m",
            ))
        self.assertIsNone(result)

    def test_generate_articles_returns_none_on_unparseable_output(self):
        result_dict = {"choices": [{"message": {"content": "not json at all"}}]}
        with patch.object(llm, "complete", AsyncMock(return_value=result_dict)):
            result = asyncio.run(llm.generate_articles(
                [{"role": "user", "content": "x"}],
                max_tokens=5, temperature=0.1, max_count=4, url="http://model", model="m",
            ))
        self.assertIsNone(result)

    def test_generate_articles_bounds_and_clamps_output(self):
        content = json.dumps([
            {"headline": "H" * 210, "blurb": "B" * 610, "section": "Weather"},
            {"headline": "Second", "blurb": "blurb", "section": "Public Works"},
            {"headline": "Third", "blurb": "blurb", "section": "Not A Section"},
            {"headline": "Fourth", "blurb": "blurb", "section": "City Hall"},
            {"headline": "Fifth", "blurb": "blurb", "section": "Public Safety"},
        ])
        result_dict = {"choices": [{"message": {"content": content}}]}
        with patch.object(llm, "complete", AsyncMock(return_value=result_dict)):
            result = asyncio.run(llm.generate_articles(
                [{"role": "user", "content": "x"}],
                max_tokens=5, temperature=0.1, max_count=3, url="http://model", model="m",
            ))
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3)  # max_count respected despite 5 candidates
        self.assertEqual(len(result[0]["headline"]), 200)  # oversized headline clamped
        self.assertEqual(len(result[0]["blurb"]), 600)     # oversized blurb clamped
        self.assertEqual(result[2]["section"], "City Hall")  # unknown section normalised


if __name__ == "__main__":
    unittest.main()

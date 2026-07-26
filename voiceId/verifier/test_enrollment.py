from __future__ import annotations

import unittest
from array import array

from voiceid_verifier.audio_quality import SpeechWindow
from voiceid_verifier.embeddings import ExtractedSpeakerEmbedding
from voiceid_verifier.enrollment import (
    MINIMUM_LEAVE_ONE_OUT_STABILITY,
    aggregate_template,
    embedding_medoid_index,
)


class EnrollmentAggregationTest(unittest.TestCase):
    def test_selects_the_most_central_embedding_as_medoid(self) -> None:
        embeddings = extracted_embeddings(
            ([1.0, 0.0], [0.98, 0.2], [0.96, -0.1], [0.5, 0.866])
        )

        selected = embedding_medoid_index(embeddings)

        self.assertEqual(selected, 1)

    def test_downweights_an_outlying_window(self) -> None:
        embeddings = extracted_embeddings(
            ([1.0, 0.0], [0.99, 0.05], [0.98, -0.05], [0.5, 0.866])
        )

        aggregation = aggregate_template(equal_windows(4), embeddings)

        self.assertLess(aggregation.weights[3], aggregation.weights[0])
        self.assertAlmostEqual(sum(aggregation.weights), 1.0)

    def test_reports_unstable_leave_one_out_template(self) -> None:
        embeddings = extracted_embeddings(
            ([1.0, 0.0], [0.866, 0.5], [0.5, 0.866], [0.5, 0.866])
        )

        aggregation = aggregate_template(equal_windows(4), embeddings)

        self.assertLess(
            aggregation.minimum_leave_one_out_similarity,
            MINIMUM_LEAVE_ONE_OUT_STABILITY,
        )

    def test_reports_stable_coherent_template(self) -> None:
        embeddings = extracted_embeddings(
            ([1.0, 0.0], [0.99, 0.02], [0.98, -0.03], [0.97, 0.04])
        )

        aggregation = aggregate_template(equal_windows(4), embeddings)

        self.assertGreaterEqual(
            aggregation.minimum_leave_one_out_similarity,
            MINIMUM_LEAVE_ONE_OUT_STABILITY,
        )
        self.assertAlmostEqual(
            sum(value * value for value in aggregation.embedding),
            1.0,
        )


def extracted_embeddings(
    vectors: tuple[list[float], ...],
) -> list[ExtractedSpeakerEmbedding]:
    return [
        ExtractedSpeakerEmbedding(vector=list(vector), speaker_label="unknown_speaker")
        for vector in vectors
    ]


def equal_windows(count: int) -> tuple[SpeechWindow, ...]:
    return tuple(
        SpeechWindow(
            start_ms=index * 2500,
            end_ms=(index + 1) * 2500,
            speech_ms=2000,
            signal_score=0.9,
            samples=array("f", [0.1, -0.1]),
        )
        for index in range(count)
    )


if __name__ == "__main__":
    unittest.main()

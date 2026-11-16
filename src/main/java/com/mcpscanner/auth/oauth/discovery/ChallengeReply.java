package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Optional;

interface ChallengeReply {

    int STREAMED_SUCCESS = 200;

    Optional<HttpResponse> answer();

    Optional<ChallengeResponse> asChallengeResponse();

    record Answered(HttpResponse response) implements ChallengeReply {

        @Override
        public Optional<HttpResponse> answer() {
            return Optional.of(response);
        }

        @Override
        public Optional<ChallengeResponse> asChallengeResponse() {
            return Optional.of(new ChallengeResponse(
                    response.statusCode(), Optional.ofNullable(response.headerValue("WWW-Authenticate"))));
        }
    }

    record Streamed() implements ChallengeReply {

        @Override
        public Optional<HttpResponse> answer() {
            return Optional.empty();
        }

        @Override
        public Optional<ChallengeResponse> asChallengeResponse() {
            return Optional.of(new ChallengeResponse(STREAMED_SUCCESS, Optional.empty()));
        }
    }

    record Silent() implements ChallengeReply {

        @Override
        public Optional<HttpResponse> answer() {
            return Optional.empty();
        }

        @Override
        public Optional<ChallengeResponse> asChallengeResponse() {
            return Optional.empty();
        }
    }
}

# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Anonymous visitors shorten URLs; authenticated users manage their own links; administrators monitor the service, security signals, and system health.

## Product Purpose

Short URL Generator creates compact links, redirects visitors safely, and gives owners and administrators the controls needed to manage links, usage, security, and service health.

## Positioning

The service combines URL shortening with secure management identifiers, abuse protection, deduplication, caching, analytics, and an owner dashboard.

## Operating Context

Users operate the service in a browser on desktop and mobile. Administrators need fast scanning of operational metrics and security state; link owners need to create, review, copy, edit, and delete URLs.

## Capabilities and Constraints

The existing API, authentication flows, embedded HTML delivery, Redis-backed persistence, URL validation, and current field identifiers must remain functional. The admin panel uses an API key; the user panel uses JWT access and refresh tokens.

## Product Principles

- Make the next operational action obvious.
- Treat link state and security state as first-class information.
- Preserve familiar browser controls and responsive behavior.
- Prefer honest, compact status language over decorative noise.

## Accessibility & Inclusion

Panels must support keyboard focus, readable contrast, labels for controls, reduced motion, and usable layouts at mobile widths.

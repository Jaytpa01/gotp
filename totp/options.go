package totp

import "hash"

type option func(*TOTP)

func (o *TOTP) applyOpts(opts ...option) {
	for _, opt := range opts {
		opt(o)
	}
}

func WithDigits(digits int) option {
	return func(o *TOTP) {
		o.digits = digits
	}
}

func WithHashingAlgorithm(algorithm func() hash.Hash) option {
	return func(o *TOTP) {
		o.hashingAlgorithm = algorithm
	}
}

func WithPeriod(period int) option {
	return func(o *TOTP) {
		o.period = period
	}
}

func WithWindow(window int) option {
	return func(o *TOTP) {
		o.window = window
	}
}

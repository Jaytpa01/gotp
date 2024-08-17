package hotp

import "hash"

type option func(*HOTP)

func (o *HOTP) applyOpts(opts ...option) {
	for _, opt := range opts {
		opt(o)
	}
}

func WithDigits(digits int) option {
	return func(o *HOTP) {
		o.digits = digits
	}
}

func WithHashingAlgorithm(algorithm func() hash.Hash) option {
	return func(o *HOTP) {
		o.hashingAlgorithm = algorithm
	}
}

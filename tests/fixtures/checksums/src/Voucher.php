<?php
// A gift-card / voucher code accepted on the strength of its check digit.
final class Voucher
{
    public static function luhn(string $digits): bool
    {
        $sum = 0;
        $alt = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $n = (int) $digits[$i];
            if ($alt) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $alt = !$alt;
        }
        return $sum % 10 === 0;
    }

    public function redeem(string $code): bool
    {
        if (!self::luhn($code)) {
            return false;
        }
        return $this->credit($code, 50);
    }

    private function credit(string $code, int $amount): bool { return true; }
}

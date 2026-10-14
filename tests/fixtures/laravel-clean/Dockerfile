FROM php:8.3-fpm-alpine
WORKDIR /var/www
COPY composer.json composer.lock ./
RUN composer install --no-dev
COPY . .
RUN php artisan optimize
USER www-data
HEALTHCHECK CMD php-fpm-healthcheck || exit 1

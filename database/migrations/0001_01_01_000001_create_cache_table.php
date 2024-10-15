<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('cache', function (Blueprint $table) {
            $table->string('key', 191)->primary(); // Key column with a shortened length
            $table->mediumText('value');
            $table->integer('expiration');
        });


        Schema::create('cache_locks', function (Blueprint $table) {
            $table->string('key', 191)->primary(); // Shorten length from 255 to 191
            $table->string('owner', 191);
            $table->integer('expiration');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('cache');
        Schema::dropIfExists('cache_locks');
    }
};
